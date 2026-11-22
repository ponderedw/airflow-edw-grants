import os
import re
import urllib.parse

import pandas as pd
from fastapi import FastAPI, Form, Request
from fastapi.responses import HTMLResponse, JSONResponse, RedirectResponse
from fastapi.templating import Jinja2Templates
try:
    from airflow.sdk.bases.hook import BaseHook  # Airflow 3
except ImportError:
    from airflow.hooks.base import BaseHook  # Airflow 2 fallback
from airflow.models import Variable
from airflow.plugins_manager import AirflowPlugin
from pydantic import BaseModel
from sqlalchemy import (
    Column,
    MetaData,
    String,
    Table,
    case,
    create_engine,
    func,
    select,
    text,
)
URL_PREFIX = "/edw_grants"

app = FastAPI()
_template_dir = os.path.join(os.path.dirname(__file__), "templates")
templates = Jinja2Templates(directory=_template_dir)

_metadata = MetaData()
pg_user_t = Table("pg_user", _metadata, Column("usename", String), schema="pg_catalog")
svv_roles_t = Table("SVV_ROLES", _metadata, Column("role_name", String), schema="pg_catalog")


# ---------------------------------------------------------------------------
# Identifier helpers
# ---------------------------------------------------------------------------

def sanitize_identifier(identifier):
    if re.match(r"^[A-Za-z0-9_]+$", identifier):
        return
    if re.match(r"^[A-Za-z0-9_.@:\-+]+$", identifier):
        return
    raise ValueError(f"Invalid identifier format: {identifier}")


def sanitize_identifiers(identifiers):
    for identifier in identifiers:
        sanitize_identifier(identifier)


def quote_identifier(identifier):
    """Wrap in double-quotes when the identifier contains characters beyond simple alphanumeric (e.g. IAM:user@domain.com)."""
    if not re.match(r"^[A-Za-z0-9_]+$", identifier):
        escaped = identifier.replace('"', '""')
        return f'"{escaped}"'
    return identifier


def is_iam_user(username: str) -> bool:
    return username.upper().startswith("IAM:")


# ---------------------------------------------------------------------------
# Connection helpers
# ---------------------------------------------------------------------------

def get_edw_connection_uri():
    conn_name = Variable.get("redshift_connection_grants_name", default_var="edw_con")
    conn = BaseHook.get_connection(conn_name)
    # Build URI manually so special chars in passwords are always URL-encoded
    # and the redshift+psycopg2 dialect is used regardless of conn_type.
    login = urllib.parse.quote(conn.login or "", safe="")
    password = urllib.parse.quote(conn.password or "", safe="")
    host = conn.host or ""
    port = conn.port or 5439
    schema = conn.schema or ""
    return f"postgresql+psycopg2://{login}:{password}@{host}:{port}/{schema}"


def get_edw_engine():
    return create_engine(get_edw_connection_uri())


def get_edw_database():
    return get_edw_connection_uri().split("/")[-1]


# ---------------------------------------------------------------------------
# Data access
# ---------------------------------------------------------------------------

def get_all_roles_list(engine):
    query = select(svv_roles_t.c.role_name.label("role_name"))
    compiled = query.compile(engine, compile_kwargs={"literal_binds": True})
    df = pd.read_sql(str(compiled), con=engine)
    return df["role_name"].tolist()


def get_roles_dependencies(engine):
    downstream = svv_roles_t.alias("dependent_roles")
    upstream = svv_roles_t.alias("roles")
    query = (
        select(
            downstream.c.role_name.label("role_downstream"),
            upstream.c.role_name.label("role_upstream"),
        )
        .where(
            func.role_is_member_of(downstream.c.role_name, upstream.c.role_name)
            | (downstream.c.role_name == upstream.c.role_name)
        )
        .distinct()
    )
    compiled = query.compile(engine, compile_kwargs={"literal_binds": True})
    df = pd.read_sql(str(compiled), con=engine)
    df = (
        df.groupby("role_downstream")["role_upstream"]
        .agg(lambda x: list(set(x)))
        .reset_index()
    )
    return df.sort_values(by=["role_downstream"]).to_dict("records")


def get_users(engine, database_name):
    query = select(
        pg_user_t.c.usename.label("username"),
        svv_roles_t.c.role_name,
        func.has_database_privilege(pg_user_t.c.usename, database_name, "CREATE").label(
            "can_create"
        ),
    ).select_from(
        pg_user_t.outerjoin(
            svv_roles_t,
            func.user_is_member_of(pg_user_t.c.usename, svv_roles_t.c.role_name),
        )
    )
    compiled = query.compile(engine, compile_kwargs={"literal_binds": True})
    df = pd.read_sql(str(compiled), con=engine)
    df_roles = (
        df.groupby("username")["role_name"]
        .agg(lambda x: list(set(x)))
        .reset_index()
    )
    df_unique = df[["username", "can_create"]].drop_duplicates()
    df = df_unique.merge(df_roles, on="username")
    return df.sort_values(by=["username"]).to_dict("records")


def _roles_roles_query(role_name, must_granted_list=None):
    if must_granted_list is None:
        must_granted_list = []
    return (
        select(
            svv_roles_t.c.role_name.label("object_name"),
            func.role_is_member_of(role_name, svv_roles_t.c.role_name).label("granted"),
            case(
                (svv_roles_t.c.role_name.in_(must_granted_list), True),
                else_=False,
            ).label("must_granted"),
        )
        .where(svv_roles_t.c.role_name != role_name)
        .cte()
    )


def _users_roles_query(user_name, must_granted_list=None):
    if must_granted_list is None:
        must_granted_list = []
    return select(
        svv_roles_t.c.role_name.label("object_name"),
        func.user_is_member_of(user_name, svv_roles_t.c.role_name).label("granted"),
        case(
            (svv_roles_t.c.role_name.in_(must_granted_list), True),
            else_=False,
        ).label("must_granted"),
    ).cte()


def _grant_revoke_query(base_query):
    return select(
        base_query.c.object_name,
        (base_query.c.granted != base_query.c.must_granted).label("ind_relevant"),
        case(
            (base_query.c.must_granted == text("True"), "grant"),
            else_="revoke",
        ).label("grant_type"),
    )


def _compute_grants(engine, base_query):
    final_query = _grant_revoke_query(base_query)
    compiled = final_query.compile(engine, compile_kwargs={"literal_binds": True})
    df = pd.read_sql(str(compiled), con=engine)
    return df[df["ind_relevant"]].to_dict("records")


def _apply_grants(engine, grants, object_name, grant_q, revoke_q):
    sanitize_identifiers([g["grant_type"] for g in grants] + [object_name])
    quoted = quote_identifier(object_name)
    with engine.connect() as conn:
        with conn.begin():
            for g in grants:
                q = (grant_q if g["grant_type"] == "grant" else revoke_q).format(
                    object_name=quoted, up_role_name=g["object_name"]
                )
                print(f"PLUGIN QUERY: {q}")
                conn.execute(text(q))


def edit_roles_roles(engine, role_name, must_granted_list):
    _apply_grants(
        engine,
        _compute_grants(engine, _roles_roles_query(role_name, must_granted_list)),
        role_name,
        "grant role {up_role_name} to role {object_name}",
        "revoke role {up_role_name} from role {object_name}",
    )


def edit_users_roles(engine, user_name, must_granted_list):
    _apply_grants(
        engine,
        _compute_grants(engine, _users_roles_query(user_name, must_granted_list)),
        user_name,
        "grant role {up_role_name} to {object_name}",
        "revoke role {up_role_name} from {object_name}",
    )


def _validate_redshift_password(password: str) -> str | None:
    if not any(c.isupper() for c in password):
        return "Password must contain at least one uppercase letter."
    if not any(c.islower() for c in password):
        return "Password must contain at least one lowercase letter."
    if not any(c.isdigit() for c in password):
        return "Password must contain at least one digit."
    return None


# ---------------------------------------------------------------------------
# Pydantic request models
# ---------------------------------------------------------------------------

class DeleteRoleBody(BaseModel):
    role_downstream: str


class DeleteUserBody(BaseModel):
    user_name: str


class DisableUserBody(BaseModel):
    user_name: str


class UpdateDbGrantBody(BaseModel):
    username: str
    status: str


class EditRoleBody(BaseModel):
    role_name: str
    roles: list[str]


class EditUserBody(BaseModel):
    user_name: str
    roles: list[str]


# ---------------------------------------------------------------------------
# Routes
# ---------------------------------------------------------------------------

@app.get("/", response_class=HTMLResponse)
async def main(request: Request, flash: str = None):
    try:
        uri = get_edw_connection_uri()
        engine = create_engine(uri)
        database_name = uri.split("/")[-1]
        roles = get_roles_dependencies(engine)
        users = get_users(engine, database_name)
        error = None
    except Exception as e:
        print(f"PLUGIN FAILURE: {e}")
        roles, users, error = [], [], f"Could not connect to EDW: {e}"
    return templates.TemplateResponse(request, "edw_grants.html", {
        "roles": roles,
        "users": users,
        "error": error,
        "flash": flash,
        "prefix": URL_PREFIX,
    })


@app.delete("/delete_role")
async def delete_role(body: DeleteRoleBody):
    try:
        engine = get_edw_engine()
        sanitize_identifiers([body.role_downstream])
        with engine.connect() as conn:
            with conn.begin():
                conn.execute(text(f"drop role {body.role_downstream}"))
        return JSONResponse({"Status": "Succeeded"})
    except Exception as e:
        print(f"PLUGIN FAILURE: {e}")
        return JSONResponse({"Status": "Failed"}, status_code=500)


@app.delete("/delete_user")
async def delete_user(body: DeleteUserBody):
    try:
        engine = get_edw_engine()
        sanitize_identifiers([body.user_name])
        quoted = quote_identifier(body.user_name)
        with engine.connect() as conn:
            with conn.begin():
                conn.execute(text(f"drop user {quoted}"))
        return JSONResponse({"Status": "Succeeded"})
    except Exception as e:
        print(f"PLUGIN FAILURE: {e}")
        return JSONResponse({"Status": "Failed"}, status_code=500)


@app.put("/disable_user")
async def disable_user(body: DisableUserBody):
    try:
        engine = get_edw_engine()
        sanitize_identifiers([body.user_name])
        quoted = quote_identifier(body.user_name)
        with engine.connect() as conn:
            with conn.begin():
                conn.execute(text(f"ALTER USER {quoted} PASSWORD DISABLE"))
        return JSONResponse({"Status": "Succeeded"})
    except Exception as e:
        print(f"PLUGIN FAILURE: {e}")
        return JSONResponse({"Status": "Failed"}, status_code=500)


@app.get("/add_role_page", response_class=HTMLResponse)
async def add_role_page_get(request: Request):
    try:
        all_roles = get_all_roles_list(get_edw_engine())
    except Exception as e:
        print(f"PLUGIN FAILURE: {e}")
        all_roles = []
    return templates.TemplateResponse(request, "add_role.html", {
        "all_roles": all_roles,
        "prefix": URL_PREFIX,
    })


@app.post("/add_role_page")
async def add_role_page_post(
    role_name: str = Form(...),
    roles: list[str] = Form(default=[]),
):
    try:
        engine = get_edw_engine()
        sanitize_identifiers([role_name] + roles)
        with engine.connect() as conn:
            with conn.begin():
                conn.execute(text(f"create role {role_name}"))
                for r in roles:
                    conn.execute(text(f"grant role {r} to role {role_name}"))
    except Exception as e:
        print(f"PLUGIN FAILURE: {e}")
    return RedirectResponse(url=f"{URL_PREFIX}/", status_code=302)


@app.get("/edit_role_page/{role_name}/{roles}", response_class=HTMLResponse)
async def edit_role_page_get(request: Request, role_name: str, roles: str):
    try:
        all_roles = get_all_roles_list(get_edw_engine())
    except Exception as e:
        print(f"PLUGIN FAILURE: {e}")
        all_roles = []
    return templates.TemplateResponse(request, "edit_role.html", {
        "role_name": role_name,
        "current_roles": [r for r in roles.split(",") if r],
        "all_roles": all_roles,
        "prefix": URL_PREFIX,
    })


@app.put("/edit_role_page/{role_name}/{roles}")
async def edit_role_page_put(role_name: str, roles: str, body: EditRoleBody):
    try:
        engine = get_edw_engine()
        edit_roles_roles(engine, body.role_name, body.roles)
        return JSONResponse({
            "message": "Role updated successfully",
            "role_name": body.role_name,
            "roles": body.roles,
        })
    except Exception as e:
        print(f"PLUGIN FAILURE: {e}")
        return JSONResponse({"message": "Failed"}, status_code=500)


@app.get("/edit_user_page/{user_name}/{roles}", response_class=HTMLResponse)
async def edit_user_page_get(request: Request, user_name: str, roles: str):
    try:
        all_roles = get_all_roles_list(get_edw_engine())
    except Exception as e:
        print(f"PLUGIN FAILURE: {e}")
        all_roles = []
    return templates.TemplateResponse(request, "edit_user.html", {
        "user_name": user_name,
        "current_roles": [r for r in roles.split(",") if r],
        "all_roles": all_roles,
        "prefix": URL_PREFIX,
    })


@app.put("/edit_user_page/{user_name}/{roles}")
async def edit_user_page_put(user_name: str, roles: str, body: EditUserBody):
    try:
        engine = get_edw_engine()
        edit_users_roles(engine, body.user_name, body.roles)
        return JSONResponse({"message": "User updated successfully", "roles": body.roles})
    except Exception as e:
        print(f"PLUGIN FAILURE: {e}")
        return JSONResponse({"message": "Failed"}, status_code=500)


@app.get("/add_user_page", response_class=HTMLResponse)
async def add_user_page_get(request: Request, error: str = None):
    try:
        all_roles = get_all_roles_list(get_edw_engine())
    except Exception as e:
        print(f"PLUGIN FAILURE: {e}")
        all_roles = []
    return templates.TemplateResponse(request, "add_user.html", {
        "all_roles": all_roles,
        "error": error,
        "prefix": URL_PREFIX,
    })


@app.post("/add_user_page")
async def add_user_page_post(
    username: str = Form(...),
    password: str = Form(default=""),
    roles: list[str] = Form(default=[]),
    can_edit_database: str = Form(default=""),
):
    iam = is_iam_user(username)

    if not iam:
        pw_error = _validate_redshift_password(password)
        if pw_error:
            return RedirectResponse(
                url=f"{URL_PREFIX}/add_user_page?error={pw_error}", status_code=302
            )

    try:
        engine = get_edw_engine()
        database_name = get_edw_database()
        sanitize_identifiers([username, database_name] + roles)
        quoted_username = quote_identifier(username)
        with engine.connect() as conn:
            with conn.begin():
                if iam:
                    # IAM users authenticate via AWS — no Redshift password needed
                    conn.execute(
                        text(f"create user {quoted_username} password disable")
                    )
                else:
                    conn.execute(
                        text(f"create user {quoted_username} password :password"),
                        {"password": password},
                    )
                for r in roles:
                    conn.execute(text(f"grant role {r} to {quoted_username}"))
                if can_edit_database:
                    conn.execute(
                        text(
                            f"grant create on database {database_name}"
                            f" to {quoted_username}"
                        )
                    )
    except Exception as e:
        print(f"PLUGIN FAILURE: {e}")
    return RedirectResponse(url=f"{URL_PREFIX}/", status_code=302)


@app.put("/update_edit_db_grant")
async def update_edit_db_grant(body: UpdateDbGrantBody):
    try:
        engine = get_edw_engine()
        database_name = get_edw_database()
        sanitize_identifiers([body.username, database_name])
        quoted_username = quote_identifier(body.username)
        if body.status == "true":
            q = f"grant create on database {database_name} to {quoted_username}"
        else:
            q = f"revoke create on database {database_name} from {quoted_username}"
        with engine.connect() as conn:
            with conn.begin():
                conn.execute(text(q))
        return JSONResponse({"Status": "Succeeded"})
    except Exception as e:
        print(f"PLUGIN FAILURE: {e}")
        return JSONResponse({"Status": "Failed"}, status_code=500)


# ---------------------------------------------------------------------------
# Plugin registration
# ---------------------------------------------------------------------------

class AirflowEdwGrantsPlugin(AirflowPlugin):
    name = "edw_grants_plugin"
    fastapi_apps = [{
        "app": app,
        "url_prefix": "/edw_grants",
        "name": "EDW Grants",
    }]
    external_views = [{
        "name": "Permissions",
        "href": "/edw_grants/",
        "destination": "nav",
        "category": "browse",
        "url_route": "edw_grants",
    }]

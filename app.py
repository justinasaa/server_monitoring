
import ipaddress
import math
import re
import sqlite3
from contextlib import contextmanager
from datetime import datetime
from pathlib import Path
from urllib.parse import quote, urlencode

from flask import Flask, Response, abort, jsonify, request
from werkzeug.exceptions import HTTPException
from werkzeug.security import generate_password_hash

BASE = Path(__file__).resolve().parent
app = Flask(__name__)

TABLES = {
    "users": {
        "key": "username", "parent": None,
        "create": ("username", "role", "name", "surname", "mail", "password"),
        "edit": ("role", "name", "surname", "mail", "password"),
        "show": ("username", "role", "name", "surname", "mail"),
        "filters": ("username", "role", "name", "surname", "mail"),
    },
    "servers": {
        "key": "ip", "parent": "owner_username",
        "create": ("ip",), "edit": ("ip",),
        "show": ("ip", "owner_username"), "filters": ("ip",),
    },
    "apps": {
        "key": "id", "parent": "server_ip",
        "create": ("name", "version"), "edit": ("name", "version"),
        "show": ("id", "server_ip", "name", "version"),
        "filters": ("name", "version"),
    },
    "resources": {
        "key": "id", "parent": "app_id",
        "create": ("datetime", "value", "name"),
        "edit": ("datetime", "value", "name"),
        "show": ("id", "app_id", "datetime", "value", "name"),
        "filters": ("name", "min_value", "max_value", "from", "to"),
    },
}
CHILD = {"users": "servers", "servers": "apps", "apps": "resources"}
SCHEMA_SQL = """
CREATE TABLE IF NOT EXISTS users (
    username TEXT PRIMARY KEY, role TEXT NOT NULL,
    name TEXT NOT NULL, surname TEXT NOT NULL,
    mail TEXT NOT NULL UNIQUE, password_hash TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS servers (
    ip TEXT PRIMARY KEY,
    owner_username TEXT NOT NULL REFERENCES users(username)
);
CREATE TABLE IF NOT EXISTS apps (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    server_ip TEXT NOT NULL REFERENCES servers(ip),
    name TEXT NOT NULL, version TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS resources (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    app_id INTEGER NOT NULL REFERENCES apps(id),
    datetime TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
    value REAL NOT NULL, name TEXT NOT NULL
);
"""


def find_database():
    db = BASE / "database.db"
    if db.exists():
        return db
    legacy = BASE / "database.sql"
    if legacy.exists() and legacy.read_bytes()[:16] == b"SQLite format 3\x00":
        return legacy  
    sql_text = legacy.read_text(encoding="utf-8-sig") if legacy.exists() else SCHEMA_SQL
    try:
        with sqlite3.connect(db) as con:
            con.executescript(sql_text)
    except Exception:
        db.unlink(missing_ok=True)
        raise
    return db


DB_PATH = find_database()


def connect():
    db = sqlite3.connect(DB_PATH)
    db.row_factory = sqlite3.Row
    db.execute("PRAGMA foreign_keys = ON")
    return db


@contextmanager
def db_session():
    db = connect()
    try:
        yield db
        db.commit()
    except Exception:
        db.rollback()
        raise
    finally:
        db.close()


def err(code, message):
    abort(code, description=message)


def public(row, kind):
    # Slaptazodzio hash niekada nepatenka i API.
    return {field: row[field] for field in TABLES[kind]["show"]}


def row_or_404(db, query, args=()):
    row = db.execute(query, args).fetchone()
    if row is None:
        err(404, "Objektas nerastas arba nepriklauso nurodytam teviniam objektui")
    return row


def check_parent(db, kind, username=None, ip=None, app_id=None):
    if kind == "users":
        return None
    row_or_404(db, "SELECT username FROM users WHERE username=?", (username,))
    if kind == "servers":
        return username
    row_or_404(db, "SELECT ip FROM servers WHERE ip=? AND owner_username=?", (ip, username))
    if kind == "apps":
        return ip
    row_or_404(db, "SELECT id FROM apps WHERE id=? AND server_ip=?", (app_id, ip))
    return app_id


def read_json():
    if not request.is_json:
        err(400, "Turi buti Content-Type: application/json")
    payload = request.get_json(silent=True)
    if not isinstance(payload, dict):
        err(400, "Reikalingas taisyklingas JSON objektas")
    return payload


def timestamp_value(v):
    if not isinstance(v, str):
        err(422, "datetime turi buti datos ir laiko tekstas")
    try:
        dt = datetime.fromisoformat(v.strip().replace("Z", "+00:00"))
    except ValueError:
        err(422, "datetime formatas: YYYY-MM-DD HH:MM:SS")
    if dt.tzinfo is not None:
        err(422, "datetime pateik be laiko zonos (DB naudoja UTC)")
    return dt.strftime("%Y-%m-%d %H:%M:%S")


def finite_number(v, field):
    if isinstance(v, bool):
        err(422, f"{field} turi buti skaicius")
    try:
        n = float(v)
    except (TypeError, ValueError, OverflowError):
        err(422, f"{field} turi buti skaicius")
    if not math.isfinite(n):
        err(422, f"{field} turi buti baigtinis skaicius")
    return n


def validate(kind, payload, *, creating, partial=False):
    allowed = set(TABLES[kind]["create" if creating else "edit"])
    extra = set(payload) - allowed
    if extra:
        err(400, "Neleidziami laukai: " + ", ".join(sorted(extra)))
    required = set(allowed)
    if kind == "resources" and creating:
        required.discard("datetime")
    if kind == "users" and not creating:
        required.discard("password")
    if not partial:
        missing = required - payload.keys()
        if missing:
            err(422, "Truksta privalomu lauku: " + ", ".join(sorted(missing)))
    if not payload:
        err(422, "Pateik bent viena keiciama lauka")

    data = {}
    for field, value in payload.items():
        if field == "password":
            if not creating and value in ("", None):
                continue
            if not isinstance(value, str) or not value.strip():
                err(422, "password turi buti netuscias tekstas")
            data["password_hash"] = generate_password_hash(value)
        elif field == "value":
            data[field] = finite_number(value, field)
        elif field == "datetime":
            if creating and value in ("", None):
                continue
            data[field] = timestamp_value(value)
        else:
            if not isinstance(value, str) or not value.strip():
                err(422, f"{field} turi buti netuscias tekstas")
            data[field] = value.strip()

    if "role" in data and data["role"] not in ("user", "admin"):
        err(422, "role turi buti user arba admin")
    if kind == "resources" and "name" in data and data["name"] not in (
        "cpu_usage", "gpu_usage", "ram_usage"
    ):
        err(422, "name turi buti cpu_usage, gpu_usage arba ram_usage")
    if kind == "servers" and "ip" in data:
        try:
            ipaddress.ip_address(data["ip"])
        except ValueError:
            err(422, "ip turi buti taisyklingas IPv4 arba IPv6 adresas")
    if kind == "users" and "mail" in data and not re.fullmatch(r"[^\s@]+@[^\s@]+\.[^\s@]+", data["mail"]):
        err(422, "mail turi buti el. pasto adresas")
    if not data:
        err(422, "Nera keiciamu duomenu")
    return data


def create_item(db, kind, payload, username=None, ip=None, app_id=None):
    parent = check_parent(db, kind, username, ip, app_id)
    data = validate(kind, payload, creating=True)
    fk = TABLES[kind]["parent"]
    if fk:
        data[fk] = parent
    keys = list(data)
    result = db.execute(
        f"INSERT INTO {kind} ({', '.join(keys)}) VALUES ({', '.join('?' for _ in keys)})",
        [data[k] for k in keys],
    )
    key = data.get(TABLES[kind]["key"], result.lastrowid)
    return get_item(db, kind, key, username, ip, app_id)


def get_item(db, kind, key, username=None, ip=None, app_id=None):
    parent = check_parent(db, kind, username, ip, app_id)
    cfg = TABLES[kind]
    sql = f"SELECT * FROM {kind} WHERE {cfg['key']}=?"
    args = [key]
    if cfg["parent"]:
        sql += f" AND {cfg['parent']}=?"
        args.append(parent)
    return public(row_or_404(db, sql, args), kind)


def update_item(db, kind, key, payload, username=None, ip=None, app_id=None, *, partial=False):
    get_item(db, kind, key, username, ip, app_id)
    data = validate(kind, payload, creating=False, partial=partial)
    if kind == "servers" and data.get("ip", key) != key:
        db.execute("PRAGMA defer_foreign_keys = ON")
    fields = list(data)
    db.execute(
        f"UPDATE {kind} SET {', '.join(f'{x}=?' for x in fields)} WHERE {TABLES[kind]['key']}=?",
        [data[k] for k in fields] + [key],
    )
    if kind == "servers" and data.get("ip", key) != key:
        # Veikia ir su sena DB be ON UPDATE CASCADE.
        db.execute("UPDATE apps SET server_ip=? WHERE server_ip=?", (data["ip"], key))
    new_key = data.get("ip", key) if kind == "servers" else key
    return get_item(db, kind, new_key, username, ip, app_id)


def delete_item(db, kind, key, username=None, ip=None, app_id=None):
    get_item(db, kind, key, username, ip, app_id)
    db.execute(f"DELETE FROM {kind} WHERE {TABLES[kind]['key']}=?", (key,))


def p(v):
    return quote(str(v), safe="")


def collection_url(kind, username=None, ip=None, app_id=None):
    if kind == "users":
        return "/users"
    u = f"/users/{p(username)}"
    if kind == "servers":
        return u + "/servers"
    s = u + f"/servers/{p(ip)}"
    if kind == "apps":
        return s + "/apps"
    return s + f"/apps/{app_id}/resources"


def item_url(kind, key, username=None, ip=None, app_id=None):
    return collection_url(kind, username, ip, app_id) + "/" + p(key)


def add_links(kind, item, username=None, ip=None, app_id=None):
    key = item[TABLES[kind]["key"]]
    if kind == "users":
        username = key
    elif kind == "servers":
        username = item["owner_username"]
        ip = key
    elif kind == "apps":
        ip = item["server_ip"]
        app_id = key
    elif kind == "resources":
        app_id = item["app_id"]
    links = {
        "self": item_url(kind, key, username, ip, app_id),
        "collection": collection_url(kind, username, ip, app_id),
    }
    if kind == "users":
        links["servers"] = collection_url("servers", username)
    elif kind == "servers":
        links["owner"] = item_url("users", username)
        links["apps"] = collection_url("apps", username, ip)
    elif kind == "apps":
        links["server"] = item_url("servers", ip, username)
        links["resources"] = collection_url("resources", username, ip, app_id)
    elif kind == "resources":
        links["app"] = item_url("apps", app_id, username, ip)
    return {**item, "_links": links}


def get_pagination():
    def integer(name, default):
        raw = request.args.get(name, str(default))
        if not re.fullmatch(r"[0-9]+", raw):
            err(400, f"{name} turi buti sveikasis skaicius")
        num = int(raw)
        if num < 1 or (name == "per_page" and num > 100):
            err(422, f"{name} turi buti nuo 1 iki 100" if name == "per_page" else "page turi buti >= 1")
        return num
    return integer("page", 1), integer("per_page", 10)


def validate_query(allowed):
    unexpected = set(request.args) - set(allowed) - {"page", "per_page"}
    if unexpected:
        err(400, "Nezinomi uzklausos parametrai: " + ", ".join(sorted(unexpected)))
    for name in request.args:
        if len(request.args.getlist(name)) != 1:
            err(400, f"{name} negali buti kartojamas")


def sql_like(value):
    return "%" + value.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_") + "%"


def filter_clauses(kind):
    conditions, args = [], []
    for field in TABLES[kind]["filters"]:
        if field not in request.args:
            continue
        value = request.args[field].strip()
        if not value:
            err(422, f"{field} negali buti tuscias")
        if field == "role":
            if value not in ("user", "admin"):
                err(422, "role turi buti user arba admin")
            conditions.append("role=?")
            args.append(value)
        elif field in ("min_value", "max_value"):
            conditions.append("value " + (">=" if field == "min_value" else "<=") + " ?")
            args.append(finite_number(value, field))
        elif field in ("from", "to"):
            conditions.append("datetime " + (">=" if field == "from" else "<=") + " ?")
            args.append(timestamp_value(value))
        elif field == "name" and kind == "resources":
            if value not in ("cpu_usage", "gpu_usage", "ram_usage"):
                err(422, "name turi buti cpu_usage, gpu_usage arba ram_usage")
            conditions.append("name=?")
            args.append(value)
        else:
            conditions.append(f"{field} LIKE ? ESCAPE '\\'")
            args.append(sql_like(value))
    if kind == "resources" and "min_value" in request.args and "max_value" in request.args:
        if float(request.args["min_value"]) > float(request.args["max_value"]):
            err(422, "min_value negali virsyti max_value")
    return conditions, args


def pagelink(page, per_page):
    q = request.args.to_dict(flat=True)
    q.update(page=str(page), per_page=str(per_page))
    return request.path + "?" + urlencode(q)


def page_response(items, total, page, per_page):
    total_pages = math.ceil(total / per_page)
    return {
        "data": items,
        "pagination": {
            "page": page, "per_page": per_page, "total_items": total,
            "total_pages": total_pages,
        },
        "_links": {
            "self": pagelink(page, per_page),
            "first": pagelink(1, per_page),
            "previous": pagelink(page-1, per_page) if page > 1 else None,
            "next": pagelink(page+1, per_page) if page < total_pages else None,
            "last": pagelink(max(1, total_pages), per_page),
        },
    }


def listing(db, kind, username=None, ip=None, app_id=None):
    parent = check_parent(db, kind, username, ip, app_id)
    validate_query(TABLES[kind]["filters"])
    page, per_page = get_pagination()
    filters, args = filter_clauses(kind)
    fk = TABLES[kind]["parent"]
    if fk:
        filters.insert(0, f"{fk}=?")
        args.insert(0, parent)
    where = " WHERE " + " AND ".join(filters) if filters else ""
    total = db.execute(f"SELECT COUNT(*) FROM {kind}{where}", args).fetchone()[0]
    rows = db.execute(
        f"SELECT * FROM {kind}{where} ORDER BY {TABLES[kind]['key']} LIMIT ? OFFSET ?",
        args + [per_page, (page-1)*per_page],
    ).fetchall()
    items = [add_links(kind, public(row, kind), username, ip, app_id) for row in rows]
    return page_response(items, total, page, per_page)


@app.route("/users", methods=["GET", "POST"])
def users_collection():
    return handle_collection("users")


@app.route("/users/<username>", methods=["GET", "PUT", "PATCH", "DELETE"])
def user_item(username):
    return handle_item("users", username)


@app.route("/users/<username>/servers", methods=["GET", "POST"])
def servers_collection(username):
    return handle_collection("servers", username=username)


@app.route("/users/<username>/servers/<ip>", methods=["GET", "PUT", "PATCH", "DELETE"])
def server_item(username, ip):
    return handle_item("servers", ip, username=username)


@app.route("/users/<username>/servers/<ip>/apps", methods=["GET", "POST"])
def apps_collection(username, ip):
    return handle_collection("apps", username=username, ip=ip)


@app.route("/users/<username>/servers/<ip>/apps/<int:app_id>", methods=["GET", "PUT", "PATCH", "DELETE"])
def app_item(username, ip, app_id):
    return handle_item("apps", app_id, username=username, ip=ip)


@app.route("/users/<username>/servers/<ip>/apps/<int:app_id>/resources", methods=["GET", "POST"])
def resources_collection(username, ip, app_id):
    return handle_collection("resources", username=username, ip=ip, app_id=app_id)


@app.route("/users/<username>/servers/<ip>/apps/<int:app_id>/resources/<int:resource_id>",
           methods=["GET", "PUT", "PATCH", "DELETE"])
def resource_item(username, ip, app_id, resource_id):
    return handle_item("resources", resource_id, username=username, ip=ip, app_id=app_id)


def handle_collection(kind, username=None, ip=None, app_id=None):
    with db_session() as db:
        if request.method == "POST":
            created = create_item(db, kind, read_json(), username, ip, app_id)
            body = add_links(kind, created, username, ip, app_id)
            return jsonify(body), 201, {"Location": body["_links"]["self"]}
        return jsonify(listing(db, kind, username, ip, app_id))


def handle_item(kind, key, username=None, ip=None, app_id=None):
    with db_session() as db:
        if request.method == "DELETE":
            delete_item(db, kind, key, username, ip, app_id)
            return "", 204  # 204 privalo netureti response body
        if request.method in ("PUT", "PATCH"):
            data = update_item(db, kind, key, read_json(), username, ip, app_id,
                               partial=request.method == "PATCH")
            return jsonify(add_links(kind, data, username, ip, app_id)), 200
        return jsonify(add_links(kind, get_item(db, kind, key, username, ip, app_id),
                                 username, ip, app_id)), 200


@app.get("/dashboard")
def dashboard():
    """Aggregacija (vienas GET is USERS ir SERVERS, ne HTML)."""
    validate_query(("username", "role", "server_ip"))
    page, per_page = get_pagination()
    conditions, args = [], []
    if "username" in request.args:
        value = request.args["username"].strip()
        if not value:
            err(422, "username negali buti tuscias")
        conditions.append("u.username LIKE ? ESCAPE '\\'")
        args.append(sql_like(value))
    if "role" in request.args:
        role = request.args["role"]
        if role not in ("user", "admin"):
            err(422, "role turi buti user arba admin")
        conditions.append("u.role=?")
        args.append(role)
    if "server_ip" in request.args:
        value = request.args["server_ip"].strip()
        if not value:
            err(422, "server_ip negali buti tuscias")
        conditions.append("EXISTS (SELECT 1 FROM servers s WHERE s.owner_username=u.username "
                          "AND s.ip LIKE ? ESCAPE '\\')")
        args.append(sql_like(value))
    where = " WHERE " + " AND ".join(conditions) if conditions else ""
    with db_session() as db:
        total = db.execute("SELECT COUNT(*) FROM users u" + where, args).fetchone()[0]
        users = db.execute("SELECT u.* FROM users u" + where +
                           " ORDER BY u.username LIMIT ? OFFSET ?",
                           args + [per_page, (page-1)*per_page]).fetchall()
        # Viena uzklausa visiems psl. vartotoju serveriams, ne N+1.
        servers = {}
        if users:
            keys = [row["username"] for row in users]
            qmarks = ",".join("?" for _ in keys)
            rows = db.execute("SELECT * FROM servers WHERE owner_username IN (" + qmarks +
                              ") ORDER BY owner_username, ip", keys).fetchall()
            for row in rows:
                s = add_links("servers", public(row, "servers"))
                servers.setdefault(row["owner_username"], []).append(s)
        data = []
        for row in users:
            user = add_links("users", public(row, "users"))
            user["servers"] = servers.get(row["username"], [])
            user["server_count"] = len(user["servers"])
            data.append(user)
    result = page_response(data, total, page, per_page)
    result["description"] = "Visi vartotojai ir kiekvieno vartotojo serveriai"
    return jsonify(result), 200


@app.get("/")
def home():
    return jsonify({
        "name": "Server Monitoring REST API",
        "type": "JSON API only; no HTML/UI",
        "_links": {
            "users": "/users", "dashboard": "/dashboard",
            "openapi": "/openapi.json"
        },
        "hierarchy": "/users/{username}/servers/{ip}/apps/{app_id}/resources/{resource_id}"
    }), 200


# ----- OpenAPI 3.1: dokumentuoja visus realiai veikiancius metodus -----
def openapi_spec():
    field_schemas = {
        "username": {"type": "string", "minLength": 1},
        "role": {"type": "string", "enum": ["user", "admin"]},
        "name": {"type": "string", "minLength": 1},
        "surname": {"type": "string", "minLength": 1},
        "mail": {"type": "string", "format": "email"},
        "password": {"type": "string", "minLength": 1, "writeOnly": True},
        "ip": {"type": "string", "description": "IPv4 arba IPv6"},
        "version": {"type": "string", "minLength": 1},
        "datetime": {"type": "string", "description": "YYYY-MM-DD HH:MM:SS (UTC)"},
        "value": {"type": "number"},
        "owner_username": {"type": "string"},
        "server_ip": {"type": "string"},
        "id": {"type": "integer"},
        "app_id": {"type": "integer"},
    }
    schemas = {
        "Links": {"type": "object", "additionalProperties": {"type": ["string", "null"]}},
        "Pagination": {
            "type": "object", "properties": {
                "page": {"type": "integer"}, "per_page": {"type": "integer"},
                "total_items": {"type": "integer"}, "total_pages": {"type": "integer"}},
            "required": ["page", "per_page", "total_items", "total_pages"],
        },
        "Error": {"type": "object", "properties": {
            "error": {"type": "string"}, "status": {"type": "integer"}},
            "required": ["error", "status"]},
    }
    for kind, cfg in TABLES.items():
        title = kind.capitalize()
        read_fields = list(cfg["show"])
        schemas[title] = {
            "type": "object", "properties": {
                **{k: field_schemas[k] for k in read_fields},
                "_links": {"$ref": "#/components/schemas/Links"}},
            "required": read_fields + ["_links"]}
        for action, fields in (("Create", cfg["create"]), ("Update", cfg["edit"])):
            required = list(fields)
            if kind == "resources" and action == "Create":
                required.remove("datetime")
            if kind == "users" and action == "Update":
                required.remove("password")
            schemas[title + action] = {
                "type": "object", "additionalProperties": False,
                "properties": {k: field_schemas[k] for k in fields},
                "required": required if action == "Create" else required,
                "minProperties": 1,
            }
        schemas[title + "Page"] = {
            "type": "object", "properties": {
                "data": {"type": "array", "items": {"$ref": f"#/components/schemas/{title}"}},
                "pagination": {"$ref": "#/components/schemas/Pagination"},
                "_links": {"$ref": "#/components/schemas/Links"}},
            "required": ["data", "pagination", "_links"]}
    schemas["DashboardUser"] = {
        "allOf": [{"$ref": "#/components/schemas/Users"},
                  {"type": "object", "properties": {
                      "servers": {"type": "array", "items": {"$ref": "#/components/schemas/Servers"}},
                      "server_count": {"type": "integer"}},
                   "required": ["servers", "server_count"]}]}
    schemas["DashboardPage"] = {"type": "object", "properties": {
        "data": {"type": "array", "items": {"$ref": "#/components/schemas/DashboardUser"}},
        "pagination": {"$ref": "#/components/schemas/Pagination"},
        "_links": {"$ref": "#/components/schemas/Links"},
        "description": {"type": "string"}},
        "required": ["data", "pagination", "_links", "description"]}

    def response(code, ref=None, description=None):
        d = {"description": description or {
            200: "Sekminga", 201: "Sukurta", 204: "Istrinta (be turinio)",
            400: "Netaisyklinga uzklausa", 404: "Nerasta", 409: "Konfliktas DB",
            422: "Duomenu validacijos klaida"}.get(code, "HTTP atsakymas")}
        if ref:
            d["content"] = {"application/json": {"schema": {"$ref": "#/components/schemas/" + ref}}}
        if code == 201:
            d["headers"] = {"Location": {"description": "Sukurto objekto kelias", "schema": {"type": "string"}}}
        return d

    errors = {str(code): response(code, "Error") for code in (400, 404, 409, 422)}
    path_fields = [
        ("users", "/users", "/users/{username}", []),
        ("servers", "/users/{username}/servers", "/users/{username}/servers/{ip}", ["username"]),
        ("apps", "/users/{username}/servers/{ip}/apps", "/users/{username}/servers/{ip}/apps/{app_id}", ["username", "ip"]),
        ("resources", "/users/{username}/servers/{ip}/apps/{app_id}/resources", "/users/{username}/servers/{ip}/apps/{app_id}/resources/{resource_id}", ["username", "ip", "app_id"]),
    ]
    def path_params(names):
        return [{"name": name, "in": "path", "required": True,
                 "schema": {"type": "integer" if name in ("app_id", "resource_id") else "string"}}
                for name in names]
    def pagination_params():
        return [
            {"name": "page", "in": "query", "schema": {"type": "integer", "minimum": 1, "default": 1}},
            {"name": "per_page", "in": "query", "schema": {"type": "integer", "minimum": 1, "maximum": 100, "default": 10}},
        ]
    def filter_params(kind):
        schemas_for_filter = {"min_value": {"type": "number"}, "max_value": {"type": "number"},
                              "role": field_schemas["role"]}
        return [{"name": x, "in": "query", "required": False,
                 "schema": schemas_for_filter.get(x, {"type": "string"})}
                for x in TABLES[kind]["filters"]]
    def body_schema(ref):
        return {"required": True, "content": {"application/json": {
            "schema": {"$ref": "#/components/schemas/" + ref}}}}

    paths = {}
    for kind, col, item, parents in path_fields:
        title = kind.capitalize()
        paths[col] = {
            "get": {"tags": [title], "summary": "Gauti sarasa su puslapiavimu ir filtrais",
                    "parameters": path_params(parents) + pagination_params() + filter_params(kind),
                    "responses": {"200": response(200, title+"Page"), **errors}},
            "post": {"tags": [title], "summary": "Sukurti objekta",
                     "parameters": path_params(parents),
                     "requestBody": body_schema(title+"Create"),
                     "responses": {"201": response(201, title), **errors}},
        }
        item_key = {"users": "username", "servers": "ip", "apps": "app_id", "resources": "resource_id"}[kind]
        pp = path_params(parents + [item_key])
        paths[item] = {
            "get": {"tags": [title], "summary": "Gauti objekta", "parameters": pp,
                    "responses": {"200": response(200, title), **errors}},
            "put": {"tags": [title], "summary": "Pakeisti objekto laukus",
                    "parameters": pp, "requestBody": body_schema(title+"Update"),
                    "responses": {"200": response(200, title), **errors}},
            "patch": {"tags": [title], "summary": "Atnaujinti dalį objekto lauku",
                      "parameters": pp, "requestBody": body_schema(title+"Update"),
                      "responses": {"200": response(200, title), **errors}},
            "delete": {"tags": [title], "summary": "Istrinti objekta", "parameters": pp,
                       "responses": {"204": response(204), **errors}},
        }
        patch_schema = schemas[title+"Update"].copy()
        patch_schema["required"] = []
        schemas[title+"Patch"] = patch_schema
        paths[item]["patch"]["requestBody"] = body_schema(title+"Patch")
    paths["/dashboard"] = {"get": {"tags": ["Dashboard"],
        "summary": "Visi vartotojai ir ju serveriai viename JSON",
        "parameters": pagination_params() + [
            {"name": name, "in": "query", "schema": {"type": "string"}}
            for name in ("username", "role", "server_ip")],
        "responses": {"200": response(200, "DashboardPage"), **errors}}}
    schemas["Home"] = {"type": "object", "additionalProperties": True}
    paths["/"] = {"get": {"tags": ["Info"], "responses": {"200": response(200, "Home")}}}
    paths["/openapi.json"] = {"get": {"tags": ["Info"],
        "summary": "OpenAPI 3.1 specifikacija JSON formatu",
        "responses": {"200": {"description": "OpenAPI JSON specifikacija", "content": {
            "application/json": {"schema": {"type": "object"}}}}}}}
    return {
        "openapi": "3.1.0",
        "info": {"title": "Server Monitoring REST API", "version": "2.0.0",
                 "description": "Flask + SQLite, JSON-only: naudotojai → serveriai → programos → resursu matavimai"},
        "servers": [{"url": "http://127.0.0.1:5000"}],
        "paths": paths,
        "components": {"schemas": schemas},
    }


@app.get("/openapi.json")
def openapi_json():
    return jsonify(openapi_spec()), 200


@app.get("/docs")
def openapi_ui():
    """Swagger UI is OpenAPI 3.1 JSON; kiti API marsrutai nekeiciami."""
    html = """<!doctype html>
<html lang="lt">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>Server Monitoring API – Swagger UI</title>
  <link rel="stylesheet" href="https://cdn.jsdelivr.net/npm/swagger-ui-dist@5/swagger-ui.css">
  <style>html, body { margin: 0; padding: 0; }</style>
</head>
<body>
  <div id="swagger-ui"></div>
  <script src="https://cdn.jsdelivr.net/npm/swagger-ui-dist@5/swagger-ui-bundle.js"></script>
  <script>
    window.onload = function () {
      window.ui = SwaggerUIBundle({
        url: "/openapi.json",
        dom_id: "#swagger-ui",
        deepLinking: true,
        presets: [SwaggerUIBundle.presets.apis],
        layout: "BaseLayout"
      });
    };
  </script>
</body>
</html>"""
    return Response(html, mimetype="text/html")


@app.errorhandler(sqlite3.IntegrityError)
def database_error(exc):
    return jsonify({"status": 409, "error": "DB konfliktas: pasikartojantis raktas arba susieti duomenys"}), 409


@app.errorhandler(HTTPException)
def http_error(exc):
    return jsonify({"status": exc.code, "error": exc.description}), exc.code


if __name__ == "__main__":
    print("DB:", DB_PATH)
    print("JSON API: http://127.0.0.1:5000/")
    print("OpenAPI: http://127.0.0.1:5000/openapi.json")
    app.run(host="127.0.0.1", port=5000, debug=False)

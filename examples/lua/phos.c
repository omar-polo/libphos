/*
 * Copyright (c) 2021 Omar Polo <op@omarpolo.com>
 *
 * Permission to use, copy, modify, and distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
 * ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
 * ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
 * OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 */

#define LUA_LIB

#include <errno.h>
#include <phos.h>
#include <string.h>

#include <lua.h>

#include <lauxlib.h>
#include <lualib.h>

static int lp_client_new(lua_State*);
static int lp_server_new(lua_State*);

static int lp_client__tostring(lua_State*);
static int lp_client__gc(lua_State*);
static int lp_client_req(lua_State*);
static int lp_client_handshake(lua_State*);
static int lp_client_handshake_sync(lua_State*);
static int lp_client_response(lua_State*);
static int lp_client_response_sync(lua_State*);
static int lp_client_read(lua_State*);
static int lp_client_read_sync(lua_State*);
static int lp_client_close(lua_State*);
static int lp_client_close_sync(lua_State*);
static int lp_client_abort(lua_State*);
static int lp_client_abort_sync(lua_State*);
static int lp_client_fd(lua_State*);
static int lp_client_res(lua_State*);
static int lp_client_err(lua_State*);

static int lp_server__tostring(lua_State*);
static int lp_server__gc(lua_State*);
static int lp_server_load_kp(lua_State*);
static int lp_server_accept(lua_State*);
static int lp_server_accept_sync(lua_State*);
static int lp_server_accept_fd(lua_State*);
static int lp_server_fd(lua_State*);
static int lp_server_err(lua_State*);

static int lp_req__tostring(lua_State*);
static int lp_req__gc(lua_State*);
static int lp_req_handshake(lua_State*);
static int lp_req_handshake_sync(lua_State*);
static int lp_req_read_request(lua_State*);
static int lp_req_read_request_sync(lua_State*);
static int lp_req_reply(lua_State*);
static int lp_req_reply_flush(lua_State*);
static int lp_req_reply_sync(lua_State*);
static int lp_req_write(lua_State*);
static int lp_req_write_sync(lua_State*);
static int lp_req_close(lua_State*);
static int lp_req_close_sync(lua_State*);
static int lp_req_fd(lua_State*);
static int lp_req_line(lua_State*);
static int lp_req_err(lua_State*);

static const luaL_Reg phoslib[] = {
	{ "new_client",		lp_client_new },
	{ "new_server",		lp_server_new },
	/* placeholders */
	{ "want_read",		NULL },
	{ "want_write",		NULL },
	{ NULL, NULL}
};

static const struct luaL_Reg client_m[] = {
	{ "__tostring",		lp_client__tostring},
	{ "__gc",		lp_client__gc},
	{ "req",		lp_client_req },
	{ "handshake",		lp_client_handshake },
	{ "handshake_sync",	lp_client_handshake_sync },
	{ "response",		lp_client_response },
	{ "response_sync",	lp_client_response_sync },
	{ "read",		lp_client_read },
	{ "read_sync",		lp_client_read_sync },
	{ "abort",		lp_client_abort },
	{ "abort_sync",		lp_client_abort_sync },
	{ "close",		lp_client_close },
	{ "close_sync",		lp_client_close_sync },
	{ "fd",			lp_client_fd },
	{ "res",		lp_client_res },
	{ "err",		lp_client_err },
	{ NULL, NULL}
};

static const struct luaL_Reg server_m[] = {
	{ "__tostring",		lp_server__tostring},
	{ "__gc",		lp_server__gc},
	{ "load_keypair_file",	lp_server_load_kp },
	{ "accept",		lp_server_accept },
	{ "accept_fd",		lp_server_accept_fd },
	{ "accept_sync",	lp_server_accept_sync },
	{ "fd",			lp_server_fd },
	{ "err",		lp_server_err },
	{ NULL, NULL}
};

static const struct luaL_Reg req_m[] = {
	{ "__tostring",		lp_req__tostring},
	{ "__gc",		lp_req__gc},
	{ "handhsake",		lp_req_handshake },
	{ "handhsake_sync",	lp_req_handshake_sync },
	{ "read_request",	lp_req_read_request },
	{ "read_request_sync",	lp_req_read_request_sync },
	{ "reply",		lp_req_reply },
	{ "reply_flush",	lp_req_reply_flush },
	{ "reply_sync",		lp_req_reply_sync },
	{ "write",		lp_req_write },
	{ "write_sync",		lp_req_write_sync },
	{ "close",		lp_req_close },
	{ "close_sync",		lp_req_close_sync },
	{ "fd",			lp_req_fd },
	{ "line",		lp_req_line },
	{ "err",		lp_req_err },
	{ NULL, NULL}
};

int
luaopen_phos(lua_State *L)
{
	luaL_newlib(L, phoslib);

	lua_pushnumber(L, PHOS_WANT_WRITE);
	lua_setfield(L, -2, "want_write");
	lua_pushnumber(L, PHOS_WANT_READ);
	lua_setfield(L, -2, "want_read");

	luaL_newmetatable(L, "phos.client");
	lua_pushvalue(L, -1);
	lua_setfield(L, -2, "__index");
	luaL_setfuncs(L, client_m, 0);
	lua_pop(L, 1);

	luaL_newmetatable(L, "phos.server");
	lua_pushvalue(L, -1);
	lua_setfield(L, -2, "__index");
	luaL_setfuncs(L, server_m, 0);
	lua_pop(L, 1);

	luaL_newmetatable(L, "phos.req");
	lua_pushvalue(L, -1);
	lua_setfield(L, -2, "__index");
	luaL_setfuncs(L, req_m, 0);
	lua_pop(L, 1);

	return 1;
}

static inline struct phos_client *
checkclient(lua_State *L)
{
	struct phos_client *client;

	client = luaL_checkudata(L, 1, "phos.client");
	luaL_argcheck(L, client != NULL, 1, "`client` expected");
	return client;
}

static inline struct phos_server *
checkserver(lua_State *L)
{
	struct phos_server *server;

	server = luaL_checkudata(L, 1, "phos.server");
	luaL_argcheck(L, server != NULL, 1, "`server` expected");
	return server;
}

static inline struct phos_req *
checkreq(lua_State *L)
{
	struct phos_req *req;

	req = luaL_checkudata(L, 1, "phos.req");
	luaL_argcheck(L, req != NULL, 1, "`req` expected");
	return req;
}

static int
lp_client_new(lua_State *L)
{
	struct phos_client *client;

	if ((client = lua_newuserdata(L, sizeof(*client))) == NULL) {
		/* probably not needed? */
		lua_pushnil(L);
		return 1;
	}

	luaL_argcheck(L, phos_client_init(client) != -1, 1,
	    "phos_client_init failed");

	luaL_getmetatable(L, "phos.client");
	lua_setmetatable(L, -2);

	/* the client is already on the stack */
	return 1;
}

static int
lp_server_new(lua_State *L)
{
	struct phos_server	*serv;
	const char		*host, *port;

	if ((serv = lua_newuserdata(L, sizeof(*serv))) == NULL) {
		/* probably not needed? */
		lua_pushnil(L);
		return 1;
	}

	host = luaL_checkstring(L, 2);
	port = luaL_checkstring(L, 3);

	luaL_argcheck(L, phos_server_init(serv, host, port) != -1, 1,
	    "phos_server_init failed");

	luaL_getmetatable(L, "phos.server");
	lua_setmetatable(L, -2);

	/* the serv is already on the stack */
	return 1;
}

static int
lp_client__tostring(lua_State *L)
{
	lua_pushstring(L, "phos-client");
	return 1;
}

static int
lp_client__gc(lua_State *L)
{
	struct phos_client	*client;

	client = checkclient(L);
	phos_client_del(client);
	return 0;
}

static int
lp_client_req(lua_State *L)
{
	struct phos_client	*client;
	int			 r;
	const char		*host, *port, *req;

	client = checkclient(L);
	host = luaL_checkstring(L, 2);
	port = luaL_checkstring(L, 3);
	req  = luaL_checkstring(L, 4);

	r = phos_client_req(client, host, port, req) == -1;
	lua_pushboolean(L, r);
	return 1;
}

static int
lp_client_handshake(lua_State *L)
{
	lua_pushinteger(L, phos_client_handshake(checkclient(L)));
	return 1;
}

static int
lp_client_handshake_sync(lua_State *L)
{
	lua_pushinteger(L, phos_client_handshake_sync(checkclient(L)));
	return 1;
}

static int
lp_client_response(lua_State *L)
{
	lua_pushinteger(L, phos_client_response(checkclient(L)));
	return 1;
}

static int
lp_client_response_sync(lua_State *L)
{
	lua_pushinteger(L, phos_client_response_sync(checkclient(L)));
	return 1;
}

static int
lp_client_read(lua_State *L)
{
	struct phos_client	*client;
	ssize_t			 r;
	char			 buf[1024];

	client = checkclient(L);
	switch (r = phos_client_read(client, buf, sizeof(buf))) {
	case PHOS_WANT_READ:
	case PHOS_WANT_WRITE:
	case 0:
	case -1:
		lua_pushinteger(L, r);
		lua_pushstring(L, "");
		break;
	default:
		lua_pushinteger(L, (int)r);
		lua_pushlstring(L, buf, (size_t)r);
		break;
	}
	return 2;
}

static int
lp_client_read_sync(lua_State *L)
{
	struct phos_client	*client;
	ssize_t			 r;
	char			 buf[1024];

	client = checkclient(L);
	switch (r = phos_client_read_sync(client, buf, sizeof(buf))) {
	case 0:
	case -1:
		lua_pushstring(L, "");
		lua_pushinteger(L, r);
		break;
	default:
		lua_pushlstring(L, buf, (size_t)r);
		lua_pushinteger(L, (int)r);
		break;
	}
	return 2;
}

static int
lp_client_close(lua_State *L)
{
	lua_pushinteger(L, phos_client_close(checkclient(L)));
	return 1;
}

static int
lp_client_close_sync(lua_State *L)
{
	lua_pushinteger(L, phos_client_close_sync(checkclient(L)));
	return 1;
}

static int
lp_client_abort(lua_State *L)
{
	lua_pushinteger(L, phos_client_abort(checkclient(L)));
	return 1;
}

static int
lp_client_abort_sync(lua_State *L)
{
	lua_pushinteger(L, phos_client_abort_sync(checkclient(L)));
	return 1;
}

static int
lp_client_fd(lua_State *L)
{
	lua_pushinteger(L, phos_client_fd(checkclient(L)));
	return 1;
}

static int
lp_client_res(lua_State *L)
{
	struct phos_client	*client;

	client = checkclient(L);

	lua_pushinteger(L, client->code);
	lua_pushstring(L, client->meta);
	return 2;
}

static int
lp_client_err(lua_State *L)
{
	lua_pushstring(L, checkclient(L)->err);
	return 1;
}

static int
lp_server__tostring(lua_State *L)
{
	lua_pushstring(L, "phos-server");
	return 1;
}

static int
lp_server__gc(lua_State *L)
{
	phos_server_del(checkserver(L));
	return 0;
}

static int
lp_server_load_kp(lua_State *L)
{
	struct phos_server	*serv;
	int			 r;
	const char		*cert;
	const char		*key;

	serv = checkserver(L);
	cert = luaL_checkstring(L, 2);
	key  = luaL_checkstring(L, 3);

	r = phos_server_load_keypair_file(serv, cert, key);
	lua_pushboolean(L, r != -1);
	return 1;
}

static int
lp_server_accept(lua_State *L)
{
	struct phos_server	*serv;
	struct phos_req		 req, *luareq;
	int			 r;

	serv = checkserver(L);
	switch (r = phos_server_accept(serv, &req)) {
	case 0:
		lua_pushinteger(L, 0);
		if ((luareq = lua_newuserdata(L, sizeof(*luareq))) == NULL) {
			lua_pop(L, 1);
			lua_pushinteger(L, -1);
			lua_pushnil(L);
			return 2;
		}

		memcpy(luareq, &req, sizeof(req));
		luaL_getmetatable(L, "phos.req");
		lua_setmetatable(L, -2);
		return 2;
	default:
		lua_pushinteger(L, r);
		lua_pushnil(L);
		return 2;
	}
}

static int
lp_server_accept_sync(lua_State *L)
{
	struct phos_server	*serv;
	struct phos_req		 req, *luareq;
	int			 r;

	serv = checkserver(L);
	switch (r = phos_server_accept_sync(serv, &req)) {
	case 0:
		lua_pushinteger(L, 0);
		if ((luareq = lua_newuserdata(L, sizeof(*luareq))) == NULL) {
			lua_pop(L, 1);
			lua_pushinteger(L, -1);
			lua_pushnil(L);
			return 2;
		}

		memcpy(luareq, &req, sizeof(req));
		luaL_getmetatable(L, "phos.req");
		lua_setmetatable(L, -2);
		return 2;
	default:
		lua_pushinteger(L, r);
		lua_pushnil(L);
		return 2;
	}
}

static int
lp_server_accept_fd(lua_State *L)
{
	struct phos_server	*serv;
	struct phos_req		 req, *luareq;
	int			 fd, r;

	serv = checkserver(L);
	fd = luaL_checkinteger(L, 2);

	switch (r = phos_server_accept_fd(serv, &req, fd)) {
	case 0:
		lua_pushinteger(L, 0);
		if ((luareq = lua_newuserdata(L, sizeof(*luareq))) == NULL) {
			lua_pop(L, 1);
			lua_pushinteger(L, -1);
			lua_pushnil(L);
			return 2;
		}

		memcpy(luareq, &req, sizeof(req));
		luaL_getmetatable(L, "phos.req");
		lua_setmetatable(L, -2);
		return 2;
	default:
		lua_pushinteger(L, r);
		lua_pushnil(L);
		return 2;
	}
}

static int
lp_server_fd(lua_State *L)
{
	lua_pushinteger(L, checkserver(L)->fd);
	return 1;
}

static int
lp_server_err(lua_State *L)
{
	lua_pushstring(L, checkserver(L)->err);
	return 1;
}

static int
lp_req__tostring(lua_State *L)
{
	lua_pushstring(L, "phos-req");
	return 1;
}

static int
lp_req__gc(lua_State *L)
{
	phos_req_del(checkreq(L));
	return 0;
}

static int
lp_req_handshake(lua_State *L)
{
	lua_pushinteger(L, phos_req_handshake(checkreq(L)));
	return 1;
}

static int
lp_req_handshake_sync(lua_State *L)
{
	lua_pushinteger(L, phos_req_handshake_sync(checkreq(L)));
	return 1;
}

static int
lp_req_read_request(lua_State *L)
{
	lua_pushinteger(L, phos_req_read_request(checkreq(L)));
	return 1;
}

static int
lp_req_read_request_sync(lua_State *L)
{
	lua_pushinteger(L, phos_req_read_request_sync(checkreq(L)));
	return 1;
}

static int
lp_req_reply(lua_State *L)
{
	struct phos_req	*req;
	int		 code;
	const char	*meta;

	req  = checkreq(L);
	code = luaL_checkinteger(L, 2);
	meta = luaL_checkstring(L, 3);

	lua_pushinteger(L, phos_req_reply(req, code, meta));
	return 1;
}

static int
lp_req_reply_flush(lua_State *L)
{
	lua_pushinteger(L, phos_req_reply_flush(checkreq(L)));
	return 1;
}

static int
lp_req_reply_sync(lua_State *L)
{
	struct phos_req	*req;
	int		 code;
	const char	*meta;

	req  = checkreq(L);
	code = luaL_checkinteger(L, 2);
	meta = luaL_checkstring(L, 3);

	lua_pushinteger(L, phos_req_reply_sync(req, code, meta));
	return 1;
}

static int
lp_req_write(lua_State *L)
{
	struct phos_req	*req;
	const char	*buf;

	req = checkreq(L);
	buf = luaL_checkstring(L, 2);
	lua_pushinteger(L, phos_req_write(req, buf, strlen(buf)));
	return 1;
}

static int
lp_req_write_sync(lua_State *L)
{
	struct phos_req	*req;
	const char	*buf;

	req = checkreq(L);
	buf = luaL_checkstring(L, 2);
	lua_pushinteger(L, phos_req_write_sync(req, buf, strlen(buf)));
	return 1;
}

static int
lp_req_close(lua_State *L)
{
	lua_pushinteger(L, phos_req_close(checkreq(L)));
	return 1;
}

static int
lp_req_close_sync(lua_State *L)
{
	lua_pushinteger(L, phos_req_close_sync(checkreq(L)));
	return 1;
}

static int
lp_req_fd(lua_State *L)
{
	lua_pushinteger(L, checkreq(L)->fd);
	return 1;
}

static int
lp_req_line(lua_State *L)
{
	lua_pushstring(L, checkreq(L)->line);
	return 1;
}

static int
lp_req_err(lua_State *L)
{
	lua_pushstring(L, checkreq(L)->err);
	return 1;
}

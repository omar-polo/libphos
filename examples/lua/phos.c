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

#include <lua.h>

#include <lauxlib.h>
#include <lualib.h>

static int lp_client_new(lua_State*);

static int lp_client__tostring(lua_State*);
static int lp_client__gc(lua_State*);
static int lp_client_req(lua_State*);
static int lp_client_run(lua_State*);
static int lp_client_run_sync(lua_State*);
static int lp_client_fd(lua_State*);
static int lp_client_state(lua_State*);
static int lp_client_res(lua_State*);
static int lp_client_buf(lua_State*);
static int lp_client_abort(lua_State*);
static int lp_client_close(lua_State*);

static const luaL_Reg phoslib[] = {
	{ "new_client",		lp_client_new },
	/* placeholders */
	{ "want_read",		NULL },
	{ "want_write",		NULL },
	{ NULL, NULL}
};

static const struct luaL_Reg client_m[] = {
	{ "__tostring",		lp_client__tostring},
	{ "__gc",		lp_client__gc},
	{ "req",		lp_client_req },
	{ "run",		lp_client_run },
	{ "run_sync",		lp_client_run_sync },
	{ "fd",			lp_client_fd },
	{ "state",		lp_client_state },
	{ "res",		lp_client_res },
	{ "buf",		lp_client_buf },
	{ "abort",		lp_client_abort },
	{ "close",		lp_client_close },
	/* placeholders */
	{ "s_start",		NULL },
	{ "s_resolution",	NULL },
	{ "s_connect",		NULL },
	{ "s_handshake",	NULL },
	{ "s_post_handshake",	NULL },
	{ "s_writing_req",	NULL },
	{ "s_reading_header",	NULL },
	{ "s_reply_ready",	NULL },
	{ "s_body",		NULL },
	{ "s_closing",		NULL },
	{ "s_eof",		NULL },
	{ "s_error",		NULL },
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

	lua_pushnumber(L, PCS_START);
	lua_setfield(L, -2, "s_start");
	lua_pushnumber(L, PCS_RESOLUTION);
	lua_setfield(L, -2, "s_resolution");
	lua_pushnumber(L, PCS_CONNECT);
	lua_setfield(L, -2, "s_connect");
	lua_pushnumber(L, PCS_HANDSHAKE);
	lua_setfield(L, -2, "s_handshake");
	lua_pushnumber(L, PCS_POST_HANDSHAKE);
	lua_setfield(L, -2, "s_post_handshake");
	lua_pushnumber(L, PCS_WRITING_REQ);
	lua_setfield(L, -2, "s_writing_req");
	lua_pushnumber(L, PCS_READING_HEADER);
	lua_setfield(L, -2, "s_reading_header");
	lua_pushnumber(L, PCS_REPLY_READY);
	lua_setfield(L, -2, "s_reply_ready");
	lua_pushnumber(L, PCS_BODY);
	lua_setfield(L, -2, "s_body");
	lua_pushnumber(L, PCS_CLOSING);
	lua_setfield(L, -2, "s_closing");
	lua_pushnumber(L, PCS_EOF);
	lua_setfield(L, -2, "s_eof");
	lua_pushnumber(L, PCS_ERROR);
	lua_setfield(L, -2, "s_error");

	lua_pop(L, 1);

	return 1;
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

static struct phos_client *
checkclient(lua_State *L)
{
	struct phos_client *client;

	client = luaL_checkudata(L, 1, "phos.client");
	luaL_argcheck(L, client != NULL, 1, "`client` expected");
	return client;
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
lp_client_run(lua_State *L)
{
	struct phos_client	*client;

	client = checkclient(L);
	lua_pushinteger(L, phos_client_run(client));
	lua_pushinteger(L, phos_client_state(client));
	return 2;
}

static int
lp_client_run_sync(lua_State *L)
{
	struct phos_client	*client;

	client = checkclient(L);
	lua_pushinteger(L, phos_client_run_sync(client));
	lua_pushinteger(L, phos_client_state(client));
	return 2;
}

static int
lp_client_fd(lua_State *L)
{
	lua_pushinteger(L, phos_client_fd(checkclient(L)));
	return 1;
}

static int
lp_client_state(lua_State *L)
{
	lua_pushinteger(L, phos_client_state(checkclient(L)));
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
lp_client_buf(lua_State *L)
{
	struct phos_client *client;

	client = checkclient(L);

	lua_pushlstring(L, client->buf, client->off);
	return 1;
}

static int
lp_client_abort(lua_State *L)
{
	int r;

	r = phos_client_abort(checkclient(L)) != -1;
	lua_pushboolean(L, r);
	return 1;
}

static int
lp_client_close(lua_State *L)
{
	phos_client_close(checkclient(L));
	lua_pushnil(L);
	return 1;
}

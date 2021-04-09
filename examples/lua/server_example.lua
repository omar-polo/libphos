local phos = require('phos')

local server = phos:new_server('localhost', '1996')
server:load_keypair_file(
   "/home/op/.local/share/gmid/localhost.cert.pem",
   "/home/op/.local/share/gmid/localhost.key.pem"
)
print("the socket is", server:fd())

while true do
   local l, req = server:accept_sync()
   if l ~= 0 then
      print("l is", l)
      print("accept failed:", server:err())
      goto continue
   end

   if req:read_request_sync() == -1 then
      print("failed to read request:", req:err())
      goto continue
   end

   print("the request is", req:line())

   req:reply_sync(20, "text/gemini")
   req:write_sync("# hello, world\n")
   req:close_sync()

   ::continue::
end

local phos = require('phos')

local client = phos:new_client()
client:req("localhost.it", "", "gemini://localhost.it/index.gmi\r\n")

while true do
   local r, state = client:run_sync()

   if state == client.s_start then
      print "in start"
   elseif state == client.s_resolution then
      print "during DNS resolution"
   elseif state == client.s_connect then
      print "during connect"
   elseif state == client.s_post_handshake then
      print "TLS handshake done"
   elseif state == client.s_reply_ready then
      local code, meta = client:res()
      print(string.format("code=%d meta=%s", code, meta))
   elseif state == client.s_body then
      print(client:buf())
   elseif state == client.s_eof then
      print("EOF")
      break
   elseif state == client.s_error then
      print("an error occurred")
      break
   end
end

# To do
## HTTP keep-alive
I would like to implement persistent HTTP connections, as it is much faster to re-use the same socket if several requests are to be sent to the same server. This would require some changes in the library, as sockets are currently disposed of when every request is finished. I don't know how or if stopping a response is possible if the socket is re-used.

## Auto redirect
Optionally handle redirects so that the library potentially sends multiple requests until a non-30x code is gotten. This would mean that e.g. the headers callback is called multiple times, once for each set of headers that have been received. Maybe there should be a function in the progress objects to check whether the response is a redirect or not so that it may easily be ignored. This would of course not be possible for the raw data callback, at least not before the status code has been parsed.

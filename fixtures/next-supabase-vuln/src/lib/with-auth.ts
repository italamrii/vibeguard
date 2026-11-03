type Handler = (req: Request) => Promise<Response>;

// Named like an auth wrapper, but it only logs.
export function withAuth(handler: Handler): Handler {
  return async (req) => {
    console.log('request', req.url);
    return handler(req);
  };
}

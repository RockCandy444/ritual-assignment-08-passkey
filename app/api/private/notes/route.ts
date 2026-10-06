import { privateData } from '@/lib/passkey';
export const dynamic = 'force-dynamic';
export const GET = privateData;
// Account IDs in a query/body are ignored; the authenticated session owns the query.
export const POST = async (req: Request) => {
  const {requireSameOrigin, body, AppError, json} = await import('@/lib/security');
  try { requireSameOrigin(req); await body(req); return privateData(req); }
  catch(e) { return e instanceof AppError ? json({error:e.code,message:e.message},e.status) : json({error:'INVALID_REQUEST'},400); }
};

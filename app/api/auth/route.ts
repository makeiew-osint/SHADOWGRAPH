import { authAction, authStatus, json } from '../../../lib/key-auth';
export const dynamic = 'force-dynamic';
export async function GET(request: Request) {
  try { return await authStatus(request); }
  catch { return json({ error: 'Не удалось проверить вход. Попробуйте ещё раз.' }, 503); }
}
export async function POST(request: Request) {
  try { return await authAction(request); }
  catch { return json({ error: 'Сервис входа временно недоступен.' }, 503); }
}

import { json } from '../../../../../lib/key-auth';
export const dynamic = 'force-dynamic';
export async function GET() { return json({ error: 'Этот провайдер ещё не подключён владельцем. Сейчас доступен вход по ключу.' }, 503); }

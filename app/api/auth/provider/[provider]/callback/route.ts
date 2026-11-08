import { finishProvider } from '../../../../../../lib/social-auth';
export const dynamic = 'force-dynamic';
export async function GET(request: Request, context: { params: Promise<{ provider: string }> }) {
  return finishProvider(request, (await context.params).provider);
}

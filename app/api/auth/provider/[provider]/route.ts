import { startProvider } from '../../../../../lib/social-auth';
export const dynamic = 'force-dynamic';
export async function GET(request: Request, context: { params: Promise<{ provider: string }> }) {
  return startProvider(request, (await context.params).provider);
}

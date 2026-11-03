import { prisma } from '@/lib/prisma';

// vg-expect: endpoints/unauthenticated-data-access
export async function GET() {
  const users = await prisma.user.findMany({ select: { email: true, plan: true } });
  return Response.json(users);
}

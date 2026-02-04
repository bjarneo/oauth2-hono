import { useQuery } from '@tanstack/react-query';
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card';
import { Building2, Users, KeyRound, Coins, Link2 } from 'lucide-react';
import { getDashboardStats } from '@/api/client';

export function Dashboard() {
  const { data: stats, isLoading } = useQuery({
    queryKey: ['dashboard-stats'],
    queryFn: getDashboardStats,
  });

  const cards = [
    {
      title: 'Total Tenants',
      value: stats?.tenantCount ?? 0,
      icon: Building2,
      description: 'Active tenants',
    },
    {
      title: 'Total Clients',
      value: stats?.clientCount ?? 0,
      icon: Users,
      description: 'Registered OAuth clients',
    },
    {
      title: 'Active Refresh Tokens',
      value: stats?.activeRefreshTokens ?? 0,
      icon: Coins,
      description: 'Non-revoked tokens',
    },
    {
      title: 'Identity Providers',
      value: stats?.identityProviderCount ?? 0,
      icon: Link2,
      description: 'Federated IdPs',
    },
  ];

  return (
    <div className="space-y-6">
      <div>
        <h1 className="text-3xl font-bold tracking-tight">Dashboard</h1>
        <p className="text-muted-foreground">Overview of your OAuth2 server</p>
      </div>

      <div className="grid gap-4 md:grid-cols-2 lg:grid-cols-4">
        {cards.map((card) => (
          <Card key={card.title}>
            <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
              <CardTitle className="text-sm font-medium">{card.title}</CardTitle>
              <card.icon className="h-4 w-4 text-muted-foreground" />
            </CardHeader>
            <CardContent>
              <div className="text-2xl font-bold">
                {isLoading ? '...' : card.value.toLocaleString()}
              </div>
              <p className="text-xs text-muted-foreground">{card.description}</p>
            </CardContent>
          </Card>
        ))}
      </div>

      <div className="grid gap-4 md:grid-cols-2">
        <Card>
          <CardHeader>
            <CardTitle>Quick Actions</CardTitle>
          </CardHeader>
          <CardContent className="space-y-2">
            <a
              href="/tenants/new"
              className="block rounded-lg border p-4 hover:bg-muted transition-colors"
            >
              <div className="flex items-center gap-3">
                <Building2 className="h-5 w-5 text-primary" />
                <div>
                  <p className="font-medium">Create Tenant</p>
                  <p className="text-sm text-muted-foreground">Set up a new tenant configuration</p>
                </div>
              </div>
            </a>
            <a
              href="/tenants"
              className="block rounded-lg border p-4 hover:bg-muted transition-colors"
            >
              <div className="flex items-center gap-3">
                <KeyRound className="h-5 w-5 text-primary" />
                <div>
                  <p className="font-medium">Manage Keys</p>
                  <p className="text-sm text-muted-foreground">View and rotate signing keys</p>
                </div>
              </div>
            </a>
          </CardContent>
        </Card>

        <Card>
          <CardHeader>
            <CardTitle>System Status</CardTitle>
          </CardHeader>
          <CardContent>
            <div className="space-y-3">
              <div className="flex items-center justify-between">
                <span className="text-sm">Authorization Codes</span>
                <span className="text-sm font-medium">
                  {stats?.activeAuthorizationCodes ?? 0} active
                </span>
              </div>
              <div className="flex items-center justify-between">
                <span className="text-sm">Device Codes</span>
                <span className="text-sm font-medium">
                  {stats?.activeDeviceCodes ?? 0} pending
                </span>
              </div>
              <div className="flex items-center justify-between">
                <span className="text-sm">Refresh Tokens</span>
                <span className="text-sm font-medium">
                  {stats?.activeRefreshTokens ?? 0} active
                </span>
              </div>
            </div>
          </CardContent>
        </Card>
      </div>
    </div>
  );
}

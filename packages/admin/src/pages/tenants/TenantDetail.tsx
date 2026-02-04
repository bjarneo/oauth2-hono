import { useQuery } from '@tanstack/react-query';
import { Link, useParams } from 'react-router-dom';
import { Pencil, Users, Key, Coins, Link2 } from 'lucide-react';
import { Button } from '@/components/ui/button';
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card';
import { Badge } from '@/components/ui/badge';
import { Separator } from '@/components/ui/separator';
import { getTenant, getTenantStats } from '@/api/client';

export function TenantDetail() {
  const { tenantId } = useParams<{ tenantId: string }>();

  const { data: tenant, isLoading } = useQuery({
    queryKey: ['tenant', tenantId],
    queryFn: () => getTenant(tenantId!),
    enabled: Boolean(tenantId),
  });

  const { data: stats } = useQuery({
    queryKey: ['tenant-stats', tenantId],
    queryFn: () => getTenantStats(tenantId!),
    enabled: Boolean(tenantId),
  });

  if (isLoading) {
    return (
      <div className="flex items-center justify-center py-8">
        <div className="text-muted-foreground">Loading...</div>
      </div>
    );
  }

  if (!tenant) {
    return (
      <div className="flex items-center justify-center py-8">
        <div className="text-muted-foreground">Tenant not found</div>
      </div>
    );
  }

  const statCards = [
    {
      title: 'Clients',
      value: stats?.clientCount ?? 0,
      icon: Users,
      href: `/tenants/${tenantId}/clients`,
    },
    {
      title: 'Signing Keys',
      value: stats?.signingKeyCount ?? 0,
      icon: Key,
      href: `/tenants/${tenantId}/signing-keys`,
    },
    {
      title: 'Active Tokens',
      value: stats?.activeRefreshTokens ?? 0,
      icon: Coins,
      href: `/tenants/${tenantId}/tokens`,
    },
    {
      title: 'Identity Providers',
      value: stats?.identityProviderCount ?? 0,
      icon: Link2,
      href: `/tenants/${tenantId}/identity-providers`,
    },
  ];

  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-3xl font-bold tracking-tight">{tenant.name}</h1>
          <p className="text-muted-foreground">
            <code className="bg-muted px-1 rounded">{tenant.slug}</code>
          </p>
        </div>
        <Button asChild>
          <Link to={`/tenants/${tenantId}/edit`}>
            <Pencil className="h-4 w-4 mr-2" />
            Edit
          </Link>
        </Button>
      </div>

      <div className="grid gap-4 md:grid-cols-2 lg:grid-cols-4">
        {statCards.map((stat) => (
          <Link key={stat.title} to={stat.href}>
            <Card className="hover:bg-muted/50 transition-colors cursor-pointer">
              <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
                <CardTitle className="text-sm font-medium">{stat.title}</CardTitle>
                <stat.icon className="h-4 w-4 text-muted-foreground" />
              </CardHeader>
              <CardContent>
                <div className="text-2xl font-bold">{stat.value}</div>
              </CardContent>
            </Card>
          </Link>
        ))}
      </div>

      <div className="grid gap-6 md:grid-cols-2">
        <Card>
          <CardHeader>
            <CardTitle>Configuration</CardTitle>
            <CardDescription>Tenant settings and configuration</CardDescription>
          </CardHeader>
          <CardContent className="space-y-4">
            <div>
              <div className="text-sm font-medium">Issuer</div>
              <div className="text-sm text-muted-foreground break-all">{tenant.issuer}</div>
            </div>
            <Separator />
            <div>
              <div className="text-sm font-medium">Allowed Grants</div>
              <div className="flex flex-wrap gap-1 mt-1">
                {tenant.allowedGrants.map((grant) => (
                  <Badge key={grant} variant="secondary">
                    {grant.replace('urn:ietf:params:oauth:grant-type:', '')}
                  </Badge>
                ))}
              </div>
            </div>
            <Separator />
            <div>
              <div className="text-sm font-medium">Allowed Scopes</div>
              <div className="flex flex-wrap gap-1 mt-1">
                {tenant.allowedScopes.map((scope) => (
                  <Badge key={scope} variant="outline">
                    {scope}
                  </Badge>
                ))}
              </div>
            </div>
          </CardContent>
        </Card>

        <Card>
          <CardHeader>
            <CardTitle>Token Lifetimes</CardTitle>
            <CardDescription>Default expiration times for tokens</CardDescription>
          </CardHeader>
          <CardContent className="space-y-4">
            <div className="flex justify-between">
              <span className="text-sm">Access Token TTL</span>
              <span className="text-sm font-medium">
                {formatDuration(tenant.accessTokenTtl)}
              </span>
            </div>
            <Separator />
            <div className="flex justify-between">
              <span className="text-sm">Refresh Token TTL</span>
              <span className="text-sm font-medium">
                {formatDuration(tenant.refreshTokenTtl)}
              </span>
            </div>
            <Separator />
            <div className="flex justify-between">
              <span className="text-sm">Authorization Code TTL</span>
              <span className="text-sm font-medium">
                {formatDuration(tenant.authorizationCodeTtl)}
              </span>
            </div>
            <Separator />
            <div className="flex justify-between">
              <span className="text-sm">Device Code TTL</span>
              <span className="text-sm font-medium">
                {formatDuration(tenant.deviceCodeTtl)}
              </span>
            </div>
          </CardContent>
        </Card>

        <Card>
          <CardHeader>
            <CardTitle>Discovery Endpoints</CardTitle>
            <CardDescription>OpenID Connect discovery URLs</CardDescription>
          </CardHeader>
          <CardContent className="space-y-2">
            <EndpointLink
              label="OpenID Configuration"
              href={`/${tenant.slug}/.well-known/openid-configuration`}
            />
            <EndpointLink label="JWKS" href={`/${tenant.slug}/.well-known/jwks.json`} />
            <EndpointLink label="Authorization" href={`/${tenant.slug}/authorize`} />
            <EndpointLink label="Token" href={`/${tenant.slug}/token`} />
            <EndpointLink label="UserInfo" href={`/${tenant.slug}/userinfo`} />
          </CardContent>
        </Card>

        <Card>
          <CardHeader>
            <CardTitle>Metadata</CardTitle>
            <CardDescription>Additional tenant information</CardDescription>
          </CardHeader>
          <CardContent className="space-y-2">
            <div className="flex justify-between">
              <span className="text-sm">Created</span>
              <span className="text-sm text-muted-foreground">
                {new Date(tenant.createdAt).toLocaleString()}
              </span>
            </div>
            <div className="flex justify-between">
              <span className="text-sm">Updated</span>
              <span className="text-sm text-muted-foreground">
                {new Date(tenant.updatedAt).toLocaleString()}
              </span>
            </div>
            <div className="flex justify-between">
              <span className="text-sm">Require PKCE</span>
              <Badge variant={tenant.requirePkce ? 'success' : 'secondary'}>
                {tenant.requirePkce ? 'Yes' : 'No'}
              </Badge>
            </div>
          </CardContent>
        </Card>
      </div>
    </div>
  );
}

function EndpointLink({ label, href }: { label: string; href: string }) {
  return (
    <div className="flex items-center justify-between gap-4">
      <span className="text-sm">{label}</span>
      <code className="text-xs bg-muted px-2 py-1 rounded truncate max-w-[200px]">{href}</code>
    </div>
  );
}

function formatDuration(seconds: number): string {
  if (seconds < 60) return `${seconds}s`;
  if (seconds < 3600) return `${Math.floor(seconds / 60)}m`;
  if (seconds < 86400) return `${Math.floor(seconds / 3600)}h`;
  return `${Math.floor(seconds / 86400)}d`;
}

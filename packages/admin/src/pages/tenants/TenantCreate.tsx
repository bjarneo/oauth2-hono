import { useMutation, useQueryClient } from '@tanstack/react-query';
import { useNavigate } from 'react-router-dom';
import { useForm } from 'react-hook-form';
import { Button } from '@/components/ui/button';
import { Input } from '@/components/ui/input';
import { Label } from '@/components/ui/label';
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card';
import { Checkbox } from '@/components/ui/checkbox';
import { createTenant } from '@/api/client';
import { toast } from '@/components/ui/use-toast';
import type { CreateTenantInput, GrantType } from '@oauth2-hono/shared';

const GRANT_TYPES: { value: GrantType; label: string }[] = [
  { value: 'authorization_code', label: 'Authorization Code' },
  { value: 'client_credentials', label: 'Client Credentials' },
  { value: 'refresh_token', label: 'Refresh Token' },
  { value: 'urn:ietf:params:oauth:grant-type:device_code', label: 'Device Code' },
];

const DEFAULT_SCOPES = ['openid', 'profile', 'email', 'offline_access'];

interface FormData {
  name: string;
  slug: string;
  issuer: string;
  allowedGrants: GrantType[];
  allowedScopes: string;
  accessTokenTtl: number;
  refreshTokenTtl: number;
}

export function TenantCreate() {
  const navigate = useNavigate();
  const queryClient = useQueryClient();

  const {
    register,
    handleSubmit,
    watch,
    setValue,
    formState: { errors },
  } = useForm<FormData>({
    defaultValues: {
      name: '',
      slug: '',
      issuer: '',
      allowedGrants: ['authorization_code', 'client_credentials', 'refresh_token'],
      allowedScopes: DEFAULT_SCOPES.join(', '),
      accessTokenTtl: 3600,
      refreshTokenTtl: 2592000,
    },
  });

  const allowedGrants = watch('allowedGrants');

  const mutation = useMutation({
    mutationFn: (data: CreateTenantInput) => createTenant(data),
    onSuccess: (tenant) => {
      queryClient.invalidateQueries({ queryKey: ['tenants'] });
      toast({
        title: 'Tenant created',
        description: `Tenant "${tenant.name}" has been created successfully.`,
      });
      navigate(`/tenants/${tenant.id}`);
    },
    onError: (error) => {
      toast({
        variant: 'destructive',
        title: 'Error',
        description: error instanceof Error ? error.message : 'Failed to create tenant',
      });
    },
  });

  const onSubmit = (data: FormData) => {
    const input: CreateTenantInput = {
      name: data.name,
      slug: data.slug,
      issuer: data.issuer || undefined,
      allowedGrants: data.allowedGrants,
      allowedScopes: data.allowedScopes.split(',').map((s) => s.trim()).filter(Boolean),
      accessTokenTtl: data.accessTokenTtl,
      refreshTokenTtl: data.refreshTokenTtl,
    };
    mutation.mutate(input);
  };

  const toggleGrant = (grant: GrantType) => {
    const current = allowedGrants || [];
    if (current.includes(grant)) {
      setValue(
        'allowedGrants',
        current.filter((g) => g !== grant)
      );
    } else {
      setValue('allowedGrants', [...current, grant]);
    }
  };

  return (
    <div className="space-y-6">
      <div>
        <h1 className="text-3xl font-bold tracking-tight">Create Tenant</h1>
        <p className="text-muted-foreground">Set up a new OAuth2 tenant</p>
      </div>

      <form onSubmit={handleSubmit(onSubmit)} className="space-y-6">
        <Card>
          <CardHeader>
            <CardTitle>Basic Information</CardTitle>
            <CardDescription>Configure the tenant identity</CardDescription>
          </CardHeader>
          <CardContent className="space-y-4">
            <div className="grid gap-4 md:grid-cols-2">
              <div className="space-y-2">
                <Label htmlFor="name">Name</Label>
                <Input
                  id="name"
                  placeholder="My Application"
                  {...register('name', { required: 'Name is required' })}
                />
                {errors.name && (
                  <p className="text-sm text-destructive">{errors.name.message}</p>
                )}
              </div>
              <div className="space-y-2">
                <Label htmlFor="slug">Slug</Label>
                <Input
                  id="slug"
                  placeholder="my-app"
                  {...register('slug', {
                    required: 'Slug is required',
                    pattern: {
                      value: /^[a-z0-9-]+$/,
                      message: 'Slug must be lowercase letters, numbers, and hyphens only',
                    },
                  })}
                />
                {errors.slug && (
                  <p className="text-sm text-destructive">{errors.slug.message}</p>
                )}
                <p className="text-xs text-muted-foreground">
                  Used in URLs: /:slug/authorize, /:slug/token, etc.
                </p>
              </div>
            </div>

            <div className="space-y-2">
              <Label htmlFor="issuer">Issuer URL (optional)</Label>
              <Input
                id="issuer"
                placeholder="https://auth.example.com/my-app"
                {...register('issuer')}
              />
              <p className="text-xs text-muted-foreground">
                Leave empty to auto-generate based on the base URL
              </p>
            </div>
          </CardContent>
        </Card>

        <Card>
          <CardHeader>
            <CardTitle>Grant Types</CardTitle>
            <CardDescription>Select which OAuth2 flows are allowed</CardDescription>
          </CardHeader>
          <CardContent>
            <div className="grid gap-4 md:grid-cols-2">
              {GRANT_TYPES.map((grant) => (
                <div key={grant.value} className="flex items-center space-x-2">
                  <Checkbox
                    id={grant.value}
                    checked={allowedGrants?.includes(grant.value)}
                    onCheckedChange={() => toggleGrant(grant.value)}
                  />
                  <Label htmlFor={grant.value} className="cursor-pointer">
                    {grant.label}
                  </Label>
                </div>
              ))}
            </div>
          </CardContent>
        </Card>

        <Card>
          <CardHeader>
            <CardTitle>Scopes</CardTitle>
            <CardDescription>Configure allowed OAuth2 scopes</CardDescription>
          </CardHeader>
          <CardContent>
            <div className="space-y-2">
              <Label htmlFor="allowedScopes">Allowed Scopes</Label>
              <Input
                id="allowedScopes"
                placeholder="openid, profile, email"
                {...register('allowedScopes')}
              />
              <p className="text-xs text-muted-foreground">Comma-separated list of scopes</p>
            </div>
          </CardContent>
        </Card>

        <Card>
          <CardHeader>
            <CardTitle>Token Lifetimes</CardTitle>
            <CardDescription>Configure default token expiration times</CardDescription>
          </CardHeader>
          <CardContent>
            <div className="grid gap-4 md:grid-cols-2">
              <div className="space-y-2">
                <Label htmlFor="accessTokenTtl">Access Token TTL (seconds)</Label>
                <Input
                  id="accessTokenTtl"
                  type="number"
                  {...register('accessTokenTtl', { valueAsNumber: true })}
                />
                <p className="text-xs text-muted-foreground">Default: 3600 (1 hour)</p>
              </div>
              <div className="space-y-2">
                <Label htmlFor="refreshTokenTtl">Refresh Token TTL (seconds)</Label>
                <Input
                  id="refreshTokenTtl"
                  type="number"
                  {...register('refreshTokenTtl', { valueAsNumber: true })}
                />
                <p className="text-xs text-muted-foreground">Default: 2592000 (30 days)</p>
              </div>
            </div>
          </CardContent>
        </Card>

        <div className="flex gap-4">
          <Button type="submit" disabled={mutation.isPending}>
            {mutation.isPending ? 'Creating...' : 'Create Tenant'}
          </Button>
          <Button type="button" variant="outline" onClick={() => navigate('/tenants')}>
            Cancel
          </Button>
        </div>
      </form>
    </div>
  );
}

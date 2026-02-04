import { useEffect } from 'react';
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query';
import { useNavigate, useParams } from 'react-router-dom';
import { useForm } from 'react-hook-form';
import { Button } from '@/components/ui/button';
import { Input } from '@/components/ui/input';
import { Label } from '@/components/ui/label';
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card';
import { Checkbox } from '@/components/ui/checkbox';
import { getTenant, updateTenant } from '@/api/client';
import { toast } from '@/components/ui/use-toast';
import type { UpdateTenantInput, GrantType } from '@oauth2-hono/shared';

const GRANT_TYPES: { value: GrantType; label: string }[] = [
  { value: 'authorization_code', label: 'Authorization Code' },
  { value: 'client_credentials', label: 'Client Credentials' },
  { value: 'refresh_token', label: 'Refresh Token' },
  { value: 'urn:ietf:params:oauth:grant-type:device_code', label: 'Device Code' },
];

interface FormData {
  name: string;
  issuer: string;
  allowedGrants: GrantType[];
  allowedScopes: string;
  accessTokenTtl: number;
  refreshTokenTtl: number;
}

export function TenantEdit() {
  const { tenantId } = useParams<{ tenantId: string }>();
  const navigate = useNavigate();
  const queryClient = useQueryClient();

  const { data: tenant, isLoading } = useQuery({
    queryKey: ['tenant', tenantId],
    queryFn: () => getTenant(tenantId!),
    enabled: Boolean(tenantId),
  });

  const {
    register,
    handleSubmit,
    watch,
    setValue,
    reset,
    formState: { errors },
  } = useForm<FormData>();

  const allowedGrants = watch('allowedGrants');

  useEffect(() => {
    if (tenant) {
      reset({
        name: tenant.name,
        issuer: tenant.issuer,
        allowedGrants: tenant.allowedGrants,
        allowedScopes: tenant.allowedScopes.join(', '),
        accessTokenTtl: tenant.accessTokenTtl,
        refreshTokenTtl: tenant.refreshTokenTtl,
      });
    }
  }, [tenant, reset]);

  const mutation = useMutation({
    mutationFn: (data: UpdateTenantInput) => updateTenant(tenantId!, data),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['tenants'] });
      queryClient.invalidateQueries({ queryKey: ['tenant', tenantId] });
      toast({
        title: 'Tenant updated',
        description: 'The tenant has been updated successfully.',
      });
      navigate(`/tenants/${tenantId}`);
    },
    onError: (error) => {
      toast({
        variant: 'destructive',
        title: 'Error',
        description: error instanceof Error ? error.message : 'Failed to update tenant',
      });
    },
  });

  const onSubmit = (data: FormData) => {
    const input: UpdateTenantInput = {
      name: data.name,
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

  return (
    <div className="space-y-6">
      <div>
        <h1 className="text-3xl font-bold tracking-tight">Edit Tenant</h1>
        <p className="text-muted-foreground">
          Modify settings for <code className="bg-muted px-1 rounded">{tenant.slug}</code>
        </p>
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
                  {...register('name', { required: 'Name is required' })}
                />
                {errors.name && (
                  <p className="text-sm text-destructive">{errors.name.message}</p>
                )}
              </div>
              <div className="space-y-2">
                <Label>Slug</Label>
                <Input value={tenant.slug} disabled />
                <p className="text-xs text-muted-foreground">Slug cannot be changed</p>
              </div>
            </div>

            <div className="space-y-2">
              <Label htmlFor="issuer">Issuer URL</Label>
              <Input id="issuer" {...register('issuer')} />
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
              <Input id="allowedScopes" {...register('allowedScopes')} />
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
              </div>
              <div className="space-y-2">
                <Label htmlFor="refreshTokenTtl">Refresh Token TTL (seconds)</Label>
                <Input
                  id="refreshTokenTtl"
                  type="number"
                  {...register('refreshTokenTtl', { valueAsNumber: true })}
                />
              </div>
            </div>
          </CardContent>
        </Card>

        <div className="flex gap-4">
          <Button type="submit" disabled={mutation.isPending}>
            {mutation.isPending ? 'Saving...' : 'Save Changes'}
          </Button>
          <Button type="button" variant="outline" onClick={() => navigate(`/tenants/${tenantId}`)}>
            Cancel
          </Button>
        </div>
      </form>
    </div>
  );
}

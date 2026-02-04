import { useState } from 'react';
import { useMutation, useQueryClient } from '@tanstack/react-query';
import { useNavigate, useParams } from 'react-router-dom';
import { useForm } from 'react-hook-form';
import { Copy, Eye, EyeOff } from 'lucide-react';
import { Button } from '@/components/ui/button';
import { Input } from '@/components/ui/input';
import { Label } from '@/components/ui/label';
import { Textarea } from '@/components/ui/textarea';
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card';
import { Checkbox } from '@/components/ui/checkbox';
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from '@/components/ui/select';
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogHeader,
  DialogTitle,
} from '@/components/ui/dialog';
import { createClient } from '@/api/client';
import { toast } from '@/components/ui/use-toast';
import type { CreateClientInput, ClientType, ClientAuthMethod, GrantType, ClientWithSecret } from '@oauth2-hono/shared';

const GRANT_TYPES: { value: GrantType; label: string }[] = [
  { value: 'authorization_code', label: 'Authorization Code' },
  { value: 'client_credentials', label: 'Client Credentials' },
  { value: 'refresh_token', label: 'Refresh Token' },
  { value: 'urn:ietf:params:oauth:grant-type:device_code', label: 'Device Code' },
];

const AUTH_METHODS: { value: ClientAuthMethod; label: string }[] = [
  { value: 'client_secret_basic', label: 'Client Secret Basic (HTTP Basic Auth)' },
  { value: 'client_secret_post', label: 'Client Secret Post (Body Parameter)' },
  { value: 'none', label: 'None (Public Client)' },
];

interface FormData {
  name: string;
  description: string;
  clientType: ClientType;
  authMethod: ClientAuthMethod;
  redirectUris: string;
  allowedGrants: GrantType[];
  allowedScopes: string;
  requireConsent: boolean;
  firstParty: boolean;
}

export function ClientCreate() {
  const { tenantId } = useParams<{ tenantId: string }>();
  const navigate = useNavigate();
  const queryClient = useQueryClient();
  const [showSecret, setShowSecret] = useState(false);
  const [createdClient, setCreatedClient] = useState<ClientWithSecret | null>(null);

  const {
    register,
    handleSubmit,
    watch,
    setValue,
    formState: { errors },
  } = useForm<FormData>({
    defaultValues: {
      name: '',
      description: '',
      clientType: 'confidential',
      authMethod: 'client_secret_basic',
      redirectUris: '',
      allowedGrants: ['authorization_code', 'refresh_token'],
      allowedScopes: 'openid profile email',
      requireConsent: true,
      firstParty: false,
    },
  });

  const allowedGrants = watch('allowedGrants');
  const clientType = watch('clientType');

  const mutation = useMutation({
    mutationFn: (data: CreateClientInput) => createClient(data),
    onSuccess: (client) => {
      queryClient.invalidateQueries({ queryKey: ['clients', tenantId] });
      setCreatedClient(client);
    },
    onError: (error) => {
      toast({
        variant: 'destructive',
        title: 'Error',
        description: error instanceof Error ? error.message : 'Failed to create client',
      });
    },
  });

  const onSubmit = (data: FormData) => {
    const input: CreateClientInput = {
      tenantId: tenantId!,
      name: data.name,
      description: data.description || undefined,
      clientType: data.clientType,
      authMethod: data.authMethod,
      redirectUris: data.redirectUris.split('\n').map((s) => s.trim()).filter(Boolean),
      allowedGrants: data.allowedGrants,
      allowedScopes: data.allowedScopes.split(' ').map((s) => s.trim()).filter(Boolean),
      requireConsent: data.requireConsent,
      firstParty: data.firstParty,
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

  const copyToClipboard = (text: string) => {
    navigator.clipboard.writeText(text);
    toast({ title: 'Copied', description: 'Copied to clipboard' });
  };

  const handleDialogClose = () => {
    setCreatedClient(null);
    navigate(`/tenants/${tenantId}/clients`);
  };

  return (
    <div className="space-y-6">
      <div>
        <h1 className="text-3xl font-bold tracking-tight">Create Client</h1>
        <p className="text-muted-foreground">Register a new OAuth2 client application</p>
      </div>

      <form onSubmit={handleSubmit(onSubmit)} className="space-y-6">
        <Card>
          <CardHeader>
            <CardTitle>Basic Information</CardTitle>
            <CardDescription>Identify your application</CardDescription>
          </CardHeader>
          <CardContent className="space-y-4">
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
              <Label htmlFor="description">Description (optional)</Label>
              <Textarea
                id="description"
                placeholder="A brief description of your application"
                {...register('description')}
              />
            </div>
          </CardContent>
        </Card>

        <Card>
          <CardHeader>
            <CardTitle>Authentication</CardTitle>
            <CardDescription>Configure how the client authenticates</CardDescription>
          </CardHeader>
          <CardContent className="space-y-4">
            <div className="grid gap-4 md:grid-cols-2">
              <div className="space-y-2">
                <Label>Client Type</Label>
                <Select
                  value={clientType}
                  onValueChange={(value) => {
                    setValue('clientType', value as ClientType);
                    if (value === 'public') {
                      setValue('authMethod', 'none');
                    }
                  }}
                >
                  <SelectTrigger>
                    <SelectValue />
                  </SelectTrigger>
                  <SelectContent>
                    <SelectItem value="confidential">Confidential (Server-side)</SelectItem>
                    <SelectItem value="public">Public (SPA, Mobile, Native)</SelectItem>
                  </SelectContent>
                </Select>
              </div>
              <div className="space-y-2">
                <Label>Authentication Method</Label>
                <Select
                  value={watch('authMethod')}
                  onValueChange={(value) => setValue('authMethod', value as ClientAuthMethod)}
                  disabled={clientType === 'public'}
                >
                  <SelectTrigger>
                    <SelectValue />
                  </SelectTrigger>
                  <SelectContent>
                    {AUTH_METHODS.map((method) => (
                      <SelectItem key={method.value} value={method.value}>
                        {method.label}
                      </SelectItem>
                    ))}
                  </SelectContent>
                </Select>
              </div>
            </div>
          </CardContent>
        </Card>

        <Card>
          <CardHeader>
            <CardTitle>Redirect URIs</CardTitle>
            <CardDescription>Allowed callback URLs (one per line)</CardDescription>
          </CardHeader>
          <CardContent>
            <Textarea
              placeholder="https://myapp.com/callback
https://myapp.com/auth/callback"
              rows={4}
              {...register('redirectUris', { required: 'At least one redirect URI is required' })}
            />
            {errors.redirectUris && (
              <p className="text-sm text-destructive mt-1">{errors.redirectUris.message}</p>
            )}
          </CardContent>
        </Card>

        <Card>
          <CardHeader>
            <CardTitle>Grant Types</CardTitle>
            <CardDescription>Select which OAuth2 flows this client can use</CardDescription>
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
                placeholder="openid profile email"
                {...register('allowedScopes')}
              />
              <p className="text-xs text-muted-foreground">Space-separated list of scopes</p>
            </div>
          </CardContent>
        </Card>

        <Card>
          <CardHeader>
            <CardTitle>Consent</CardTitle>
            <CardDescription>User consent settings</CardDescription>
          </CardHeader>
          <CardContent className="space-y-4">
            <div className="flex items-center space-x-2">
              <Checkbox
                id="requireConsent"
                checked={watch('requireConsent')}
                onCheckedChange={(checked) => setValue('requireConsent', checked as boolean)}
              />
              <Label htmlFor="requireConsent" className="cursor-pointer">
                Require user consent
              </Label>
            </div>
            <div className="flex items-center space-x-2">
              <Checkbox
                id="firstParty"
                checked={watch('firstParty')}
                onCheckedChange={(checked) => setValue('firstParty', checked as boolean)}
              />
              <Label htmlFor="firstParty" className="cursor-pointer">
                First-party application (skip consent for trusted apps)
              </Label>
            </div>
          </CardContent>
        </Card>

        <div className="flex gap-4">
          <Button type="submit" disabled={mutation.isPending}>
            {mutation.isPending ? 'Creating...' : 'Create Client'}
          </Button>
          <Button
            type="button"
            variant="outline"
            onClick={() => navigate(`/tenants/${tenantId}/clients`)}
          >
            Cancel
          </Button>
        </div>
      </form>

      <Dialog open={Boolean(createdClient)} onOpenChange={handleDialogClose}>
        <DialogContent>
          <DialogHeader>
            <DialogTitle>Client Created Successfully</DialogTitle>
            <DialogDescription>
              Save these credentials securely. The client secret will not be shown again.
            </DialogDescription>
          </DialogHeader>
          <div className="space-y-4">
            <div className="space-y-2">
              <Label>Client ID</Label>
              <div className="flex items-center gap-2">
                <Input value={createdClient?.clientId ?? ''} readOnly />
                <Button
                  variant="outline"
                  size="icon"
                  onClick={() => copyToClipboard(createdClient?.clientId ?? '')}
                >
                  <Copy className="h-4 w-4" />
                </Button>
              </div>
            </div>
            {createdClient?.clientSecret && (
              <div className="space-y-2">
                <Label>Client Secret</Label>
                <div className="flex items-center gap-2">
                  <Input
                    type={showSecret ? 'text' : 'password'}
                    value={createdClient.clientSecret}
                    readOnly
                  />
                  <Button variant="outline" size="icon" onClick={() => setShowSecret(!showSecret)}>
                    {showSecret ? <EyeOff className="h-4 w-4" /> : <Eye className="h-4 w-4" />}
                  </Button>
                  <Button
                    variant="outline"
                    size="icon"
                    onClick={() => copyToClipboard(createdClient.clientSecret!)}
                  >
                    <Copy className="h-4 w-4" />
                  </Button>
                </div>
                <p className="text-xs text-destructive">
                  Save this secret now. You won't be able to see it again.
                </p>
              </div>
            )}
            <Button onClick={handleDialogClose} className="w-full">
              Done
            </Button>
          </div>
        </DialogContent>
      </Dialog>
    </div>
  );
}

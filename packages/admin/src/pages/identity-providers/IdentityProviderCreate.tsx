import { useState } from 'react';
import { useMutation, useQueryClient } from '@tanstack/react-query';
import { useNavigate, useParams } from 'react-router-dom';
import { useForm } from 'react-hook-form';
import { Button } from '@/components/ui/button';
import { Input } from '@/components/ui/input';
import { Label } from '@/components/ui/label';
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card';
import { Tabs, TabsContent, TabsList, TabsTrigger } from '@/components/ui/tabs';
import { createIdentityProvider } from '@/api/client';
import { toast } from '@/components/ui/use-toast';
import type { CreateIdentityProviderInput, IdentityProviderTemplate } from '@oauth2-hono/shared';

const PROVIDER_TEMPLATES: {
  value: IdentityProviderTemplate;
  label: string;
  icon: string;
  scopes: string[];
  issuer?: string;
}[] = [
  {
    value: 'google',
    label: 'Google',
    icon: '🔵',
    scopes: ['openid', 'email', 'profile'],
    issuer: 'https://accounts.google.com',
  },
  {
    value: 'github',
    label: 'GitHub',
    icon: '⚫',
    scopes: ['user:email', 'read:user'],
  },
  {
    value: 'microsoft',
    label: 'Microsoft',
    icon: '🟦',
    scopes: ['openid', 'email', 'profile'],
    issuer: 'https://login.microsoftonline.com/common/v2.0',
  },
  {
    value: 'apple',
    label: 'Apple',
    icon: '⬛',
    scopes: ['name', 'email'],
    issuer: 'https://appleid.apple.com',
  },
  { value: 'generic_oidc', label: 'Generic OIDC', icon: '🔗', scopes: ['openid', 'profile', 'email'] },
  { value: 'generic_oauth2', label: 'Generic OAuth2', icon: '🔗', scopes: [] },
];

interface FormData {
  name: string;
  slug: string;
  template: IdentityProviderTemplate;
  clientId: string;
  clientSecret: string;
  issuer: string;
  authorizationEndpoint: string;
  tokenEndpoint: string;
  userinfoEndpoint: string;
  scopes: string;
}

export function IdentityProviderCreate() {
  const { tenantId } = useParams<{ tenantId: string }>();
  const navigate = useNavigate();
  const queryClient = useQueryClient();
  const [selectedTemplate, setSelectedTemplate] = useState<IdentityProviderTemplate | null>(null);

  const {
    register,
    handleSubmit,
    setValue,
    watch,
    formState: { errors },
  } = useForm<FormData>({
    defaultValues: {
      name: '',
      slug: '',
      template: 'generic_oidc',
      clientId: '',
      clientSecret: '',
      issuer: '',
      authorizationEndpoint: '',
      tokenEndpoint: '',
      userinfoEndpoint: '',
      scopes: 'openid profile email',
    },
  });

  const mutation = useMutation({
    mutationFn: (data: CreateIdentityProviderInput) => createIdentityProvider(data),
    onSuccess: (provider) => {
      queryClient.invalidateQueries({ queryKey: ['identity-providers', tenantId] });
      toast({
        title: 'Provider created',
        description: `${provider.name} has been configured.`,
      });
      navigate(`/tenants/${tenantId}/identity-providers/${provider.id}`);
    },
    onError: (error) => {
      toast({
        variant: 'destructive',
        title: 'Error',
        description: error instanceof Error ? error.message : 'Failed to create provider',
      });
    },
  });

  const handleTemplateSelect = (template: IdentityProviderTemplate) => {
    setSelectedTemplate(template);
    const config = PROVIDER_TEMPLATES.find((t) => t.value === template);
    if (config) {
      setValue('template', template);
      setValue('name', config.label);
      setValue('slug', template.replace('_', '-'));
      setValue('scopes', config.scopes.join(' '));
      if (config.issuer) {
        setValue('issuer', config.issuer);
      }
    }
  };

  const onSubmit = (data: FormData) => {
    const isOidc = data.template.includes('oidc') || ['google', 'microsoft', 'apple'].includes(data.template);
    const input: CreateIdentityProviderInput = {
      tenantId: tenantId!,
      name: data.name,
      slug: data.slug,
      template: data.template,
      type: isOidc ? 'oidc' : 'oauth2',
      clientId: data.clientId,
      clientSecret: data.clientSecret,
      issuer: data.issuer || undefined,
      authorizationEndpoint: data.authorizationEndpoint || undefined,
      tokenEndpoint: data.tokenEndpoint || undefined,
      userinfoEndpoint: data.userinfoEndpoint || undefined,
      scopes: data.scopes.split(' ').filter(Boolean),
      enabled: true,
    };
    mutation.mutate(input);
  };

  if (!selectedTemplate) {
    return (
      <div className="space-y-6">
        <div>
          <h1 className="text-3xl font-bold tracking-tight">Add Identity Provider</h1>
          <p className="text-muted-foreground">Choose a provider to configure</p>
        </div>

        <div className="grid gap-4 md:grid-cols-2 lg:grid-cols-3">
          {PROVIDER_TEMPLATES.map((template) => (
            <Card
              key={template.value}
              className="cursor-pointer hover:border-primary transition-colors"
              onClick={() => handleTemplateSelect(template.value)}
            >
              <CardHeader>
                <div className="flex items-center gap-3">
                  <span className="text-2xl">{template.icon}</span>
                  <CardTitle className="text-lg">{template.label}</CardTitle>
                </div>
              </CardHeader>
              <CardContent>
                <p className="text-sm text-muted-foreground">
                  {template.value.includes('generic')
                    ? 'Configure a custom provider'
                    : `Sign in with ${template.label}`}
                </p>
              </CardContent>
            </Card>
          ))}
        </div>
      </div>
    );
  }

  const isGeneric = selectedTemplate.includes('generic');
  const isOidc = selectedTemplate.includes('oidc') || ['google', 'microsoft', 'apple'].includes(selectedTemplate);

  return (
    <div className="space-y-6">
      <div>
        <h1 className="text-3xl font-bold tracking-tight">
          Configure {PROVIDER_TEMPLATES.find((t) => t.value === selectedTemplate)?.label}
        </h1>
        <p className="text-muted-foreground">Enter your OAuth2 application credentials</p>
      </div>

      <form onSubmit={handleSubmit(onSubmit)} className="space-y-6">
        <Card>
          <CardHeader>
            <CardTitle>Basic Information</CardTitle>
            <CardDescription>Identify this provider</CardDescription>
          </CardHeader>
          <CardContent className="space-y-4">
            <div className="grid gap-4 md:grid-cols-2">
              <div className="space-y-2">
                <Label htmlFor="name">Display Name</Label>
                <Input
                  id="name"
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
                  {...register('slug', {
                    required: 'Slug is required',
                    pattern: {
                      value: /^[a-z0-9-]+$/,
                      message: 'Lowercase letters, numbers, and hyphens only',
                    },
                  })}
                />
                {errors.slug && (
                  <p className="text-sm text-destructive">{errors.slug.message}</p>
                )}
                <p className="text-xs text-muted-foreground">
                  Used in URLs: /:tenant/federate/{watch('slug')}
                </p>
              </div>
            </div>
          </CardContent>
        </Card>

        <Card>
          <CardHeader>
            <CardTitle>OAuth2 Credentials</CardTitle>
            <CardDescription>
              {isGeneric
                ? 'Enter your OAuth2 application credentials'
                : `Get these from your ${PROVIDER_TEMPLATES.find((t) => t.value === selectedTemplate)?.label} developer console`}
            </CardDescription>
          </CardHeader>
          <CardContent className="space-y-4">
            <div className="grid gap-4 md:grid-cols-2">
              <div className="space-y-2">
                <Label htmlFor="clientId">Client ID</Label>
                <Input
                  id="clientId"
                  {...register('clientId', { required: 'Client ID is required' })}
                />
                {errors.clientId && (
                  <p className="text-sm text-destructive">{errors.clientId.message}</p>
                )}
              </div>
              <div className="space-y-2">
                <Label htmlFor="clientSecret">Client Secret</Label>
                <Input
                  id="clientSecret"
                  type="password"
                  {...register('clientSecret', { required: 'Client Secret is required' })}
                />
                {errors.clientSecret && (
                  <p className="text-sm text-destructive">{errors.clientSecret.message}</p>
                )}
              </div>
            </div>
          </CardContent>
        </Card>

        {isGeneric && (
          <Card>
            <CardHeader>
              <CardTitle>Endpoints</CardTitle>
              <CardDescription>
                {isOidc
                  ? 'Enter the issuer URL for OIDC discovery, or configure endpoints manually'
                  : 'Configure the OAuth2 endpoints'}
              </CardDescription>
            </CardHeader>
            <CardContent className="space-y-4">
              {isOidc ? (
                <Tabs defaultValue="discovery">
                  <TabsList>
                    <TabsTrigger value="discovery">OIDC Discovery</TabsTrigger>
                    <TabsTrigger value="manual">Manual</TabsTrigger>
                  </TabsList>
                  <TabsContent value="discovery" className="space-y-4">
                    <div className="space-y-2">
                      <Label htmlFor="issuer">Issuer URL</Label>
                      <Input
                        id="issuer"
                        placeholder="https://example.com"
                        {...register('issuer')}
                      />
                      <p className="text-xs text-muted-foreground">
                        Endpoints will be auto-discovered from .well-known/openid-configuration
                      </p>
                    </div>
                  </TabsContent>
                  <TabsContent value="manual" className="space-y-4">
                    <EndpointFields register={register} />
                  </TabsContent>
                </Tabs>
              ) : (
                <EndpointFields register={register} />
              )}
            </CardContent>
          </Card>
        )}

        <Card>
          <CardHeader>
            <CardTitle>Scopes</CardTitle>
            <CardDescription>OAuth2 scopes to request</CardDescription>
          </CardHeader>
          <CardContent>
            <div className="space-y-2">
              <Label htmlFor="scopes">Scopes</Label>
              <Input id="scopes" {...register('scopes')} />
              <p className="text-xs text-muted-foreground">Space-separated list of scopes</p>
            </div>
          </CardContent>
        </Card>

        <div className="flex gap-4">
          <Button type="submit" disabled={mutation.isPending}>
            {mutation.isPending ? 'Creating...' : 'Create Provider'}
          </Button>
          <Button
            type="button"
            variant="outline"
            onClick={() => setSelectedTemplate(null)}
          >
            Back
          </Button>
        </div>
      </form>
    </div>
  );
}

function EndpointFields({ register }: { register: ReturnType<typeof useForm<FormData>>['register'] }) {
  return (
    <>
      <div className="space-y-2">
        <Label htmlFor="authorizationEndpoint">Authorization Endpoint</Label>
        <Input
          id="authorizationEndpoint"
          placeholder="https://example.com/authorize"
          {...register('authorizationEndpoint')}
        />
      </div>
      <div className="space-y-2">
        <Label htmlFor="tokenEndpoint">Token Endpoint</Label>
        <Input
          id="tokenEndpoint"
          placeholder="https://example.com/token"
          {...register('tokenEndpoint')}
        />
      </div>
      <div className="space-y-2">
        <Label htmlFor="userinfoEndpoint">UserInfo Endpoint</Label>
        <Input
          id="userinfoEndpoint"
          placeholder="https://example.com/userinfo"
          {...register('userinfoEndpoint')}
        />
      </div>
    </>
  );
}

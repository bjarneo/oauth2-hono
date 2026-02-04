import { useState } from 'react';
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query';
import { useParams, useNavigate } from 'react-router-dom';
import { Trash2, Power, PowerOff } from 'lucide-react';
import { Button } from '@/components/ui/button';
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card';
import { Badge } from '@/components/ui/badge';
import { Separator } from '@/components/ui/separator';
import {
  AlertDialog,
  AlertDialogAction,
  AlertDialogCancel,
  AlertDialogContent,
  AlertDialogDescription,
  AlertDialogFooter,
  AlertDialogHeader,
  AlertDialogTitle,
} from '@/components/ui/alert-dialog';
import { getIdentityProvider, deleteIdentityProvider, updateIdentityProvider } from '@/api/client';
import { toast } from '@/components/ui/use-toast';

export function IdentityProviderDetail() {
  const { tenantId, providerId } = useParams<{ tenantId: string; providerId: string }>();
  const navigate = useNavigate();
  const queryClient = useQueryClient();
  const [deleteDialogOpen, setDeleteDialogOpen] = useState(false);

  const { data: provider, isLoading } = useQuery({
    queryKey: ['identity-provider', providerId],
    queryFn: () => getIdentityProvider(providerId!),
    enabled: Boolean(providerId),
  });

  const deleteMutation = useMutation({
    mutationFn: deleteIdentityProvider,
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['identity-providers', tenantId] });
      toast({
        title: 'Provider deleted',
        description: 'The identity provider has been deleted.',
      });
      navigate(`/tenants/${tenantId}/identity-providers`);
    },
    onError: (error) => {
      toast({
        variant: 'destructive',
        title: 'Error',
        description: error instanceof Error ? error.message : 'Failed to delete provider',
      });
    },
  });

  const toggleMutation = useMutation({
    mutationFn: (enabled: boolean) => updateIdentityProvider(providerId!, { enabled }),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['identity-provider', providerId] });
      toast({ title: 'Provider updated' });
    },
    onError: (error) => {
      toast({
        variant: 'destructive',
        title: 'Error',
        description: error instanceof Error ? error.message : 'Failed to update provider',
      });
    },
  });

  if (isLoading) {
    return (
      <div className="flex items-center justify-center py-8">
        <div className="text-muted-foreground">Loading...</div>
      </div>
    );
  }

  if (!provider) {
    return (
      <div className="flex items-center justify-center py-8">
        <div className="text-muted-foreground">Provider not found</div>
      </div>
    );
  }

  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-3xl font-bold tracking-tight">{provider.name}</h1>
          <p className="text-muted-foreground">
            <code className="bg-muted px-1 rounded">{provider.slug}</code>
          </p>
        </div>
        <div className="flex gap-2">
          <Button
            variant="outline"
            onClick={() => toggleMutation.mutate(!provider.enabled)}
          >
            {provider.enabled ? (
              <>
                <PowerOff className="h-4 w-4 mr-2" />
                Disable
              </>
            ) : (
              <>
                <Power className="h-4 w-4 mr-2" />
                Enable
              </>
            )}
          </Button>
          <Button variant="destructive" onClick={() => setDeleteDialogOpen(true)}>
            <Trash2 className="h-4 w-4 mr-2" />
            Delete
          </Button>
        </div>
      </div>

      <div className="grid gap-6 md:grid-cols-2">
        <Card>
          <CardHeader>
            <CardTitle>Configuration</CardTitle>
            <CardDescription>Provider settings</CardDescription>
          </CardHeader>
          <CardContent className="space-y-4">
            <div className="flex justify-between items-center">
              <span className="text-sm">Status</span>
              {provider.enabled ? (
                <Badge variant="success">Enabled</Badge>
              ) : (
                <Badge variant="secondary">Disabled</Badge>
              )}
            </div>
            <Separator />
            <div className="flex justify-between items-center">
              <span className="text-sm">Type</span>
              <Badge variant="outline">{provider.type.toUpperCase()}</Badge>
            </div>
            <Separator />
            <div className="flex justify-between items-center">
              <span className="text-sm">Template</span>
              <code className="text-xs bg-muted px-2 py-1 rounded">
                {provider.template || 'custom'}
              </code>
            </div>
          </CardContent>
        </Card>

        <Card>
          <CardHeader>
            <CardTitle>OAuth2 Credentials</CardTitle>
            <CardDescription>Authentication configuration</CardDescription>
          </CardHeader>
          <CardContent className="space-y-4">
            <div>
              <div className="text-sm font-medium">Client ID</div>
              <code className="text-sm bg-muted px-2 py-1 rounded block mt-1 break-all">
                {provider.clientId}
              </code>
            </div>
            <Separator />
            <div>
              <div className="text-sm font-medium">Client Secret</div>
              <code className="text-sm bg-muted px-2 py-1 rounded block mt-1">
                ••••••••••••••••
              </code>
            </div>
          </CardContent>
        </Card>

        <Card>
          <CardHeader>
            <CardTitle>Endpoints</CardTitle>
            <CardDescription>OAuth2/OIDC endpoints</CardDescription>
          </CardHeader>
          <CardContent className="space-y-4">
            {provider.issuer && (
              <div>
                <div className="text-sm font-medium">Issuer</div>
                <code className="text-xs bg-muted px-2 py-1 rounded block mt-1 break-all">
                  {provider.issuer}
                </code>
              </div>
            )}
            {provider.authorizationEndpoint && (
              <>
                <Separator />
                <div>
                  <div className="text-sm font-medium">Authorization</div>
                  <code className="text-xs bg-muted px-2 py-1 rounded block mt-1 break-all">
                    {provider.authorizationEndpoint}
                  </code>
                </div>
              </>
            )}
            {provider.tokenEndpoint && (
              <>
                <Separator />
                <div>
                  <div className="text-sm font-medium">Token</div>
                  <code className="text-xs bg-muted px-2 py-1 rounded block mt-1 break-all">
                    {provider.tokenEndpoint}
                  </code>
                </div>
              </>
            )}
            {provider.userinfoEndpoint && (
              <>
                <Separator />
                <div>
                  <div className="text-sm font-medium">UserInfo</div>
                  <code className="text-xs bg-muted px-2 py-1 rounded block mt-1 break-all">
                    {provider.userinfoEndpoint}
                  </code>
                </div>
              </>
            )}
          </CardContent>
        </Card>

        <Card>
          <CardHeader>
            <CardTitle>Scopes</CardTitle>
            <CardDescription>Requested OAuth2 scopes</CardDescription>
          </CardHeader>
          <CardContent>
            <div className="flex flex-wrap gap-2">
              {provider.scopes.map((scope) => (
                <Badge key={scope} variant="outline">
                  {scope}
                </Badge>
              ))}
            </div>
          </CardContent>
        </Card>

        <Card className="md:col-span-2">
          <CardHeader>
            <CardTitle>Federation URL</CardTitle>
            <CardDescription>Use this URL to initiate authentication</CardDescription>
          </CardHeader>
          <CardContent>
            <code className="text-sm bg-muted px-3 py-2 rounded block break-all">
              /[tenant-slug]/federate/{provider.slug}
            </code>
            <p className="text-xs text-muted-foreground mt-2">
              Include <code>redirect_uri</code> and <code>state</code> query parameters
            </p>
          </CardContent>
        </Card>
      </div>

      <AlertDialog open={deleteDialogOpen} onOpenChange={setDeleteDialogOpen}>
        <AlertDialogContent>
          <AlertDialogHeader>
            <AlertDialogTitle>Delete Identity Provider</AlertDialogTitle>
            <AlertDialogDescription>
              Are you sure you want to delete "{provider.name}"? Users who signed up with this
              provider will no longer be able to authenticate.
            </AlertDialogDescription>
          </AlertDialogHeader>
          <AlertDialogFooter>
            <AlertDialogCancel>Cancel</AlertDialogCancel>
            <AlertDialogAction
              onClick={() => deleteMutation.mutate(provider.id)}
              className="bg-destructive text-destructive-foreground hover:bg-destructive/90"
            >
              Delete
            </AlertDialogAction>
          </AlertDialogFooter>
        </AlertDialogContent>
      </AlertDialog>
    </div>
  );
}

import { useState } from 'react';
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query';
import { useParams, useNavigate } from 'react-router-dom';
import { Copy, RefreshCw, Trash2, Eye, EyeOff } from 'lucide-react';
import { Button } from '@/components/ui/button';
import { Input } from '@/components/ui/input';
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
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogHeader,
  DialogTitle,
} from '@/components/ui/dialog';
import { getClient, deleteClient, regenerateClientSecret } from '@/api/client';
import { toast } from '@/components/ui/use-toast';

export function ClientDetail() {
  const { tenantId, clientId } = useParams<{ tenantId: string; clientId: string }>();
  const navigate = useNavigate();
  const queryClient = useQueryClient();
  const [deleteDialogOpen, setDeleteDialogOpen] = useState(false);
  const [newSecret, setNewSecret] = useState<string | null>(null);
  const [showSecret, setShowSecret] = useState(false);

  const { data: client, isLoading } = useQuery({
    queryKey: ['client', clientId],
    queryFn: () => getClient(clientId!),
    enabled: Boolean(clientId),
  });

  const deleteMutation = useMutation({
    mutationFn: deleteClient,
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['clients', tenantId] });
      toast({
        title: 'Client deleted',
        description: 'The client has been deleted successfully.',
      });
      navigate(`/tenants/${tenantId}/clients`);
    },
    onError: (error) => {
      toast({
        variant: 'destructive',
        title: 'Error',
        description: error instanceof Error ? error.message : 'Failed to delete client',
      });
    },
  });

  const regenerateMutation = useMutation({
    mutationFn: () => regenerateClientSecret(clientId!),
    onSuccess: (data) => {
      setNewSecret(data.clientSecret);
      toast({
        title: 'Secret regenerated',
        description: 'A new client secret has been generated.',
      });
    },
    onError: (error) => {
      toast({
        variant: 'destructive',
        title: 'Error',
        description: error instanceof Error ? error.message : 'Failed to regenerate secret',
      });
    },
  });

  const copyToClipboard = (text: string) => {
    navigator.clipboard.writeText(text);
    toast({ title: 'Copied', description: 'Copied to clipboard' });
  };

  if (isLoading) {
    return (
      <div className="flex items-center justify-center py-8">
        <div className="text-muted-foreground">Loading...</div>
      </div>
    );
  }

  if (!client) {
    return (
      <div className="flex items-center justify-center py-8">
        <div className="text-muted-foreground">Client not found</div>
      </div>
    );
  }

  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-3xl font-bold tracking-tight">{client.name}</h1>
          <p className="text-muted-foreground">{client.description || 'OAuth2 Client'}</p>
        </div>
        <div className="flex gap-2">
          {client.clientType === 'confidential' && (
            <Button variant="outline" onClick={() => regenerateMutation.mutate()}>
              <RefreshCw className="h-4 w-4 mr-2" />
              Regenerate Secret
            </Button>
          )}
          <Button variant="destructive" onClick={() => setDeleteDialogOpen(true)}>
            <Trash2 className="h-4 w-4 mr-2" />
            Delete
          </Button>
        </div>
      </div>

      <div className="grid gap-6 md:grid-cols-2">
        <Card>
          <CardHeader>
            <CardTitle>Credentials</CardTitle>
            <CardDescription>Client authentication credentials</CardDescription>
          </CardHeader>
          <CardContent className="space-y-4">
            <div className="space-y-2">
              <div className="text-sm font-medium">Client ID</div>
              <div className="flex items-center gap-2">
                <code className="flex-1 bg-muted px-3 py-2 rounded text-sm break-all">
                  {client.clientId}
                </code>
                <Button
                  variant="outline"
                  size="icon"
                  onClick={() => copyToClipboard(client.clientId)}
                >
                  <Copy className="h-4 w-4" />
                </Button>
              </div>
            </div>
            <Separator />
            <div className="flex justify-between items-center">
              <span className="text-sm">Client Type</span>
              <Badge variant={client.clientType === 'confidential' ? 'default' : 'secondary'}>
                {client.clientType}
              </Badge>
            </div>
            <div className="flex justify-between items-center">
              <span className="text-sm">Auth Method</span>
              <code className="text-xs bg-muted px-2 py-1 rounded">{client.authMethod}</code>
            </div>
          </CardContent>
        </Card>

        <Card>
          <CardHeader>
            <CardTitle>Redirect URIs</CardTitle>
            <CardDescription>Allowed callback URLs</CardDescription>
          </CardHeader>
          <CardContent>
            <div className="space-y-2">
              {client.redirectUris.map((uri, index) => (
                <code key={index} className="block bg-muted px-3 py-2 rounded text-sm break-all">
                  {uri}
                </code>
              ))}
            </div>
          </CardContent>
        </Card>

        <Card>
          <CardHeader>
            <CardTitle>Grant Types</CardTitle>
            <CardDescription>Allowed OAuth2 flows</CardDescription>
          </CardHeader>
          <CardContent>
            <div className="flex flex-wrap gap-2">
              {client.allowedGrants.map((grant) => (
                <Badge key={grant} variant="secondary">
                  {grant.replace('urn:ietf:params:oauth:grant-type:', '')}
                </Badge>
              ))}
            </div>
          </CardContent>
        </Card>

        <Card>
          <CardHeader>
            <CardTitle>Scopes</CardTitle>
            <CardDescription>Allowed OAuth2 scopes</CardDescription>
          </CardHeader>
          <CardContent>
            <div className="flex flex-wrap gap-2">
              {client.allowedScopes.map((scope) => (
                <Badge key={scope} variant="outline">
                  {scope}
                </Badge>
              ))}
            </div>
          </CardContent>
        </Card>

        <Card>
          <CardHeader>
            <CardTitle>Consent Settings</CardTitle>
            <CardDescription>User consent configuration</CardDescription>
          </CardHeader>
          <CardContent className="space-y-4">
            <div className="flex justify-between items-center">
              <span className="text-sm">Require Consent</span>
              <Badge variant={client.requireConsent ? 'default' : 'secondary'}>
                {client.requireConsent ? 'Yes' : 'No'}
              </Badge>
            </div>
            <div className="flex justify-between items-center">
              <span className="text-sm">First Party</span>
              <Badge variant={client.firstParty ? 'success' : 'secondary'}>
                {client.firstParty ? 'Yes' : 'No'}
              </Badge>
            </div>
          </CardContent>
        </Card>

        <Card>
          <CardHeader>
            <CardTitle>Metadata</CardTitle>
            <CardDescription>Additional client information</CardDescription>
          </CardHeader>
          <CardContent className="space-y-2">
            <div className="flex justify-between">
              <span className="text-sm">Created</span>
              <span className="text-sm text-muted-foreground">
                {new Date(client.createdAt).toLocaleString()}
              </span>
            </div>
            <div className="flex justify-between">
              <span className="text-sm">Updated</span>
              <span className="text-sm text-muted-foreground">
                {new Date(client.updatedAt).toLocaleString()}
              </span>
            </div>
          </CardContent>
        </Card>
      </div>

      <AlertDialog open={deleteDialogOpen} onOpenChange={setDeleteDialogOpen}>
        <AlertDialogContent>
          <AlertDialogHeader>
            <AlertDialogTitle>Delete Client</AlertDialogTitle>
            <AlertDialogDescription>
              Are you sure you want to delete "{client.name}"? This action cannot be undone.
              All tokens issued to this client will be invalidated.
            </AlertDialogDescription>
          </AlertDialogHeader>
          <AlertDialogFooter>
            <AlertDialogCancel>Cancel</AlertDialogCancel>
            <AlertDialogAction
              onClick={() => deleteMutation.mutate(client.id)}
              className="bg-destructive text-destructive-foreground hover:bg-destructive/90"
            >
              Delete
            </AlertDialogAction>
          </AlertDialogFooter>
        </AlertDialogContent>
      </AlertDialog>

      <Dialog open={Boolean(newSecret)} onOpenChange={() => setNewSecret(null)}>
        <DialogContent>
          <DialogHeader>
            <DialogTitle>New Client Secret</DialogTitle>
            <DialogDescription>
              Save this secret securely. It will not be shown again.
            </DialogDescription>
          </DialogHeader>
          <div className="space-y-4">
            <div className="flex items-center gap-2">
              <Input
                type={showSecret ? 'text' : 'password'}
                value={newSecret ?? ''}
                readOnly
              />
              <Button variant="outline" size="icon" onClick={() => setShowSecret(!showSecret)}>
                {showSecret ? <EyeOff className="h-4 w-4" /> : <Eye className="h-4 w-4" />}
              </Button>
              <Button
                variant="outline"
                size="icon"
                onClick={() => copyToClipboard(newSecret!)}
              >
                <Copy className="h-4 w-4" />
              </Button>
            </div>
            <p className="text-xs text-destructive">
              Save this secret now. You won't be able to see it again.
            </p>
            <Button onClick={() => setNewSecret(null)} className="w-full">
              Done
            </Button>
          </div>
        </DialogContent>
      </Dialog>
    </div>
  );
}

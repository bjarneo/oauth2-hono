import { useState } from 'react';
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query';
import { Link, useParams, useNavigate } from 'react-router-dom';
import { Plus, MoreHorizontal, Trash2, Eye, Power, PowerOff, Link2 } from 'lucide-react';
import { Button } from '@/components/ui/button';
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card';
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from '@/components/ui/table';
import {
  DropdownMenu,
  DropdownMenuContent,
  DropdownMenuItem,
  DropdownMenuSeparator,
  DropdownMenuTrigger,
} from '@/components/ui/dropdown-menu';
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
import { Badge } from '@/components/ui/badge';
import { listIdentityProviders, deleteIdentityProvider, updateIdentityProvider } from '@/api/client';
import { toast } from '@/components/ui/use-toast';
import type { IdentityProvider } from '@oauth2-hono/shared';

export function IdentityProviderList() {
  const { tenantId } = useParams<{ tenantId: string }>();
  const navigate = useNavigate();
  const queryClient = useQueryClient();
  const [deleteDialogOpen, setDeleteDialogOpen] = useState(false);
  const [providerToDelete, setProviderToDelete] = useState<IdentityProvider | null>(null);

  const { data: providers, isLoading } = useQuery({
    queryKey: ['identity-providers', tenantId],
    queryFn: () => listIdentityProviders(tenantId!),
    enabled: Boolean(tenantId),
  });

  const deleteMutation = useMutation({
    mutationFn: deleteIdentityProvider,
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['identity-providers', tenantId] });
      toast({
        title: 'Provider deleted',
        description: 'The identity provider has been deleted.',
      });
      setDeleteDialogOpen(false);
      setProviderToDelete(null);
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
    mutationFn: ({ id, enabled }: { id: string; enabled: boolean }) =>
      updateIdentityProvider(id, { enabled }),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['identity-providers', tenantId] });
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

  const handleDelete = (provider: IdentityProvider) => {
    setProviderToDelete(provider);
    setDeleteDialogOpen(true);
  };

  const getProviderIcon = (template?: string) => {
    switch (template) {
      case 'google':
        return '🔵';
      case 'github':
        return '⚫';
      case 'microsoft':
        return '🟦';
      case 'apple':
        return '⬛';
      case 'facebook':
        return '🔷';
      default:
        return '🔗';
    }
  };

  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-3xl font-bold tracking-tight">Identity Providers</h1>
          <p className="text-muted-foreground">Configure federated authentication</p>
        </div>
        <Button asChild>
          <Link to={`/tenants/${tenantId}/identity-providers/new`}>
            <Plus className="h-4 w-4 mr-2" />
            Add Provider
          </Link>
        </Button>
      </div>

      <Card>
        <CardHeader>
          <CardTitle>Configured Providers</CardTitle>
        </CardHeader>
        <CardContent>
          {isLoading ? (
            <div className="flex items-center justify-center py-8">
              <div className="text-muted-foreground">Loading...</div>
            </div>
          ) : !providers?.length ? (
            <div className="flex flex-col items-center justify-center py-8 text-center">
              <Link2 className="h-12 w-12 text-muted-foreground mb-4" />
              <p className="text-muted-foreground mb-4">No identity providers configured</p>
              <Button asChild>
                <Link to={`/tenants/${tenantId}/identity-providers/new`}>
                  Add your first provider
                </Link>
              </Button>
            </div>
          ) : (
            <Table>
              <TableHeader>
                <TableRow>
                  <TableHead>Provider</TableHead>
                  <TableHead>Slug</TableHead>
                  <TableHead>Type</TableHead>
                  <TableHead>Status</TableHead>
                  <TableHead>Scopes</TableHead>
                  <TableHead className="w-[70px]"></TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {providers.map((provider) => (
                  <TableRow key={provider.id}>
                    <TableCell>
                      <div className="flex items-center gap-2">
                        <span className="text-lg">{getProviderIcon(provider.template)}</span>
                        <Link
                          to={`/tenants/${tenantId}/identity-providers/${provider.id}`}
                          className="font-medium hover:underline"
                        >
                          {provider.name}
                        </Link>
                      </div>
                    </TableCell>
                    <TableCell>
                      <code className="text-sm bg-muted px-1 rounded">{provider.slug}</code>
                    </TableCell>
                    <TableCell>
                      <Badge variant="outline">{provider.type.toUpperCase()}</Badge>
                    </TableCell>
                    <TableCell>
                      {provider.enabled ? (
                        <Badge variant="success">Enabled</Badge>
                      ) : (
                        <Badge variant="secondary">Disabled</Badge>
                      )}
                    </TableCell>
                    <TableCell>
                      <div className="flex flex-wrap gap-1">
                        {provider.scopes.slice(0, 2).map((scope) => (
                          <Badge key={scope} variant="outline" className="text-xs">
                            {scope}
                          </Badge>
                        ))}
                        {provider.scopes.length > 2 && (
                          <Badge variant="outline" className="text-xs">
                            +{provider.scopes.length - 2}
                          </Badge>
                        )}
                      </div>
                    </TableCell>
                    <TableCell>
                      <DropdownMenu>
                        <DropdownMenuTrigger asChild>
                          <Button variant="ghost" size="icon">
                            <MoreHorizontal className="h-4 w-4" />
                          </Button>
                        </DropdownMenuTrigger>
                        <DropdownMenuContent align="end">
                          <DropdownMenuItem
                            onClick={() =>
                              navigate(`/tenants/${tenantId}/identity-providers/${provider.id}`)
                            }
                          >
                            <Eye className="h-4 w-4 mr-2" />
                            View
                          </DropdownMenuItem>
                          <DropdownMenuItem
                            onClick={() =>
                              toggleMutation.mutate({
                                id: provider.id,
                                enabled: !provider.enabled,
                              })
                            }
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
                          </DropdownMenuItem>
                          <DropdownMenuSeparator />
                          <DropdownMenuItem
                            className="text-destructive"
                            onClick={() => handleDelete(provider)}
                          >
                            <Trash2 className="h-4 w-4 mr-2" />
                            Delete
                          </DropdownMenuItem>
                        </DropdownMenuContent>
                      </DropdownMenu>
                    </TableCell>
                  </TableRow>
                ))}
              </TableBody>
            </Table>
          )}
        </CardContent>
      </Card>

      <AlertDialog open={deleteDialogOpen} onOpenChange={setDeleteDialogOpen}>
        <AlertDialogContent>
          <AlertDialogHeader>
            <AlertDialogTitle>Delete Identity Provider</AlertDialogTitle>
            <AlertDialogDescription>
              Are you sure you want to delete "{providerToDelete?.name}"? Users who signed up
              with this provider will no longer be able to authenticate.
            </AlertDialogDescription>
          </AlertDialogHeader>
          <AlertDialogFooter>
            <AlertDialogCancel>Cancel</AlertDialogCancel>
            <AlertDialogAction
              onClick={() => providerToDelete && deleteMutation.mutate(providerToDelete.id)}
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

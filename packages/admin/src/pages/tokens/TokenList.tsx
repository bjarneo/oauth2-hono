import { useState } from 'react';
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query';
import { useParams } from 'react-router-dom';
import { XCircle, Search, Coins } from 'lucide-react';
import { Button } from '@/components/ui/button';
import { Input } from '@/components/ui/input';
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card';
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from '@/components/ui/table';
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
import { listRefreshTokens, revokeRefreshToken, revokeUserTokens } from '@/api/client';
import { toast } from '@/components/ui/use-toast';
import type { RefreshToken } from '@oauth2-hono/shared';

export function TokenList() {
  const { tenantId } = useParams<{ tenantId: string }>();
  const queryClient = useQueryClient();
  const [userIdFilter, setUserIdFilter] = useState('');
  const [revokeDialogOpen, setRevokeDialogOpen] = useState(false);
  const [revokeAllDialogOpen, setRevokeAllDialogOpen] = useState(false);
  const [tokenToRevoke, setTokenToRevoke] = useState<RefreshToken | null>(null);

  const { data, isLoading } = useQuery({
    queryKey: ['refresh-tokens', tenantId, userIdFilter],
    queryFn: () =>
      listRefreshTokens(tenantId!, {
        userId: userIdFilter || undefined,
        active: true,
      }),
    enabled: Boolean(tenantId),
  });

  const revokeMutation = useMutation({
    mutationFn: revokeRefreshToken,
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['refresh-tokens', tenantId] });
      toast({ title: 'Token revoked', description: 'The refresh token has been revoked.' });
      setRevokeDialogOpen(false);
      setTokenToRevoke(null);
    },
    onError: (error) => {
      toast({
        variant: 'destructive',
        title: 'Error',
        description: error instanceof Error ? error.message : 'Failed to revoke token',
      });
    },
  });

  const revokeAllMutation = useMutation({
    mutationFn: () => revokeUserTokens(tenantId!, userIdFilter),
    onSuccess: (result) => {
      queryClient.invalidateQueries({ queryKey: ['refresh-tokens', tenantId] });
      toast({
        title: 'Tokens revoked',
        description: `${result.revokedCount} tokens have been revoked.`,
      });
      setRevokeAllDialogOpen(false);
    },
    onError: (error) => {
      toast({
        variant: 'destructive',
        title: 'Error',
        description: error instanceof Error ? error.message : 'Failed to revoke tokens',
      });
    },
  });

  const handleRevoke = (token: RefreshToken) => {
    setTokenToRevoke(token);
    setRevokeDialogOpen(true);
  };

  const formatExpiry = (date: Date) => {
    const now = new Date();
    const expiry = new Date(date);
    const diffMs = expiry.getTime() - now.getTime();
    const diffDays = Math.ceil(diffMs / (1000 * 60 * 60 * 24));

    if (diffDays < 0) return 'Expired';
    if (diffDays === 0) return 'Today';
    if (diffDays === 1) return 'Tomorrow';
    if (diffDays < 7) return `${diffDays} days`;
    return expiry.toLocaleDateString();
  };

  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-3xl font-bold tracking-tight">Refresh Tokens</h1>
          <p className="text-muted-foreground">Manage active refresh tokens</p>
        </div>
      </div>

      <Card>
        <CardHeader>
          <CardTitle>Token Management</CardTitle>
          <CardDescription>View and revoke refresh tokens</CardDescription>
        </CardHeader>
        <CardContent className="space-y-4">
          <div className="flex gap-4">
            <div className="relative flex-1">
              <Search className="absolute left-3 top-1/2 h-4 w-4 -translate-y-1/2 text-muted-foreground" />
              <Input
                placeholder="Filter by User ID..."
                value={userIdFilter}
                onChange={(e) => setUserIdFilter(e.target.value)}
                className="pl-10"
              />
            </div>
            {userIdFilter && (
              <Button variant="destructive" onClick={() => setRevokeAllDialogOpen(true)}>
                <XCircle className="h-4 w-4 mr-2" />
                Revoke All for User
              </Button>
            )}
          </div>

          {isLoading ? (
            <div className="flex items-center justify-center py-8">
              <div className="text-muted-foreground">Loading...</div>
            </div>
          ) : !data?.data.length ? (
            <div className="flex flex-col items-center justify-center py-8 text-center">
              <Coins className="h-12 w-12 text-muted-foreground mb-4" />
              <p className="text-muted-foreground">
                {userIdFilter ? 'No tokens found for this user' : 'No active refresh tokens'}
              </p>
            </div>
          ) : (
            <Table>
              <TableHeader>
                <TableRow>
                  <TableHead>User ID</TableHead>
                  <TableHead>Client ID</TableHead>
                  <TableHead>Scope</TableHead>
                  <TableHead>Issued</TableHead>
                  <TableHead>Expires</TableHead>
                  <TableHead>Status</TableHead>
                  <TableHead className="w-[100px]">Actions</TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {data.data.map((token) => (
                  <TableRow key={token.id}>
                    <TableCell className="font-mono text-sm">
                      {token.userId || '-'}
                    </TableCell>
                    <TableCell className="font-mono text-sm">
                      {token.clientId.substring(0, 8)}...
                    </TableCell>
                    <TableCell>
                      <div className="flex flex-wrap gap-1 max-w-[200px]">
                        {token.scope?.split(' ').slice(0, 3).map((scope) => (
                          <Badge key={scope} variant="outline" className="text-xs">
                            {scope}
                          </Badge>
                        ))}
                        {token.scope && token.scope.split(' ').length > 3 && (
                          <Badge variant="outline" className="text-xs">
                            +{token.scope.split(' ').length - 3}
                          </Badge>
                        )}
                      </div>
                    </TableCell>
                    <TableCell className="text-muted-foreground">
                      {new Date(token.issuedAt).toLocaleDateString()}
                    </TableCell>
                    <TableCell className="text-muted-foreground">
                      {formatExpiry(token.expiresAt)}
                    </TableCell>
                    <TableCell>
                      {token.revokedAt ? (
                        <Badge variant="destructive">Revoked</Badge>
                      ) : new Date(token.expiresAt) < new Date() ? (
                        <Badge variant="secondary">Expired</Badge>
                      ) : (
                        <Badge variant="success">Active</Badge>
                      )}
                    </TableCell>
                    <TableCell>
                      {!token.revokedAt && new Date(token.expiresAt) >= new Date() && (
                        <Button
                          variant="ghost"
                          size="sm"
                          className="text-destructive hover:text-destructive"
                          onClick={() => handleRevoke(token)}
                        >
                          <XCircle className="h-4 w-4 mr-1" />
                          Revoke
                        </Button>
                      )}
                    </TableCell>
                  </TableRow>
                ))}
              </TableBody>
            </Table>
          )}

          {data && data.total > data.data.length && (
            <div className="text-sm text-muted-foreground text-center">
              Showing {data.data.length} of {data.total} tokens
            </div>
          )}
        </CardContent>
      </Card>

      {/* Revoke Single Token Dialog */}
      <AlertDialog open={revokeDialogOpen} onOpenChange={setRevokeDialogOpen}>
        <AlertDialogContent>
          <AlertDialogHeader>
            <AlertDialogTitle>Revoke Token</AlertDialogTitle>
            <AlertDialogDescription>
              Are you sure you want to revoke this refresh token? The user will need to
              re-authenticate to get a new token.
            </AlertDialogDescription>
          </AlertDialogHeader>
          <AlertDialogFooter>
            <AlertDialogCancel>Cancel</AlertDialogCancel>
            <AlertDialogAction
              onClick={() => tokenToRevoke && revokeMutation.mutate(tokenToRevoke.id)}
              className="bg-destructive text-destructive-foreground hover:bg-destructive/90"
            >
              Revoke
            </AlertDialogAction>
          </AlertDialogFooter>
        </AlertDialogContent>
      </AlertDialog>

      {/* Revoke All User Tokens Dialog */}
      <AlertDialog open={revokeAllDialogOpen} onOpenChange={setRevokeAllDialogOpen}>
        <AlertDialogContent>
          <AlertDialogHeader>
            <AlertDialogTitle>Revoke All User Tokens</AlertDialogTitle>
            <AlertDialogDescription>
              Are you sure you want to revoke all refresh tokens for user "{userIdFilter}"?
              This will sign them out of all devices.
            </AlertDialogDescription>
          </AlertDialogHeader>
          <AlertDialogFooter>
            <AlertDialogCancel>Cancel</AlertDialogCancel>
            <AlertDialogAction
              onClick={() => revokeAllMutation.mutate()}
              className="bg-destructive text-destructive-foreground hover:bg-destructive/90"
            >
              Revoke All
            </AlertDialogAction>
          </AlertDialogFooter>
        </AlertDialogContent>
      </AlertDialog>
    </div>
  );
}

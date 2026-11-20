import React, { useState, useEffect } from 'react';
import { Users, UserPlus, Shield, CheckCircle, XCircle, Trash2, Edit3, X, Loader2 } from 'lucide-react';
import { getUsers, updateUser, deleteUser, registerUser } from '../services/authService';
import LoadingSpinner from '../components/common/LoadingSpinner';
import ErrorBanner from '../components/common/ErrorBanner';

const UsersPage = () => {
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);
  const [users, setUsers] = useState([]);
  const [pagination, setPagination] = useState({ page: 1, limit: 20, total: 0, totalPages: 1 });
  const [showCreateModal, setShowCreateModal] = useState(false);

  // New User Form State
  const [newUser, setNewUser] = useState({ username: '', email: '', password: '', role: 'VIEWER' });
  const [createSubmitting, setCreateSubmitting] = useState(false);
  const [createError, setCreateError] = useState(null);

  // Delete User Confirmation Modal State
  const [userToDelete, setUserToDelete] = useState(null);
  const [deleteLoading, setDeleteLoading] = useState(false);
  const [deleteError, setDeleteError] = useState(null);

  const fetchUsers = async (page = 1) => {
    setLoading(true);
    setError(null);
    try {
      const res = await getUsers({ page, limit: 20 });
      setUsers(res.data || []);
      if (res.pagination) setPagination(res.pagination);
    } catch (err) {
      setError(err.message || 'Failed to fetch users list.');
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchUsers(1);
  }, []);

  const handleRoleChange = async (userId, newRole) => {
    try {
      await updateUser(userId, { role: newRole });
      fetchUsers(pagination.page);
    } catch (err) {
      alert(`Failed to update user role: ${err.message}`);
    }
  };

  const handleToggleActive = async (userId, currentStatus) => {
    try {
      await updateUser(userId, { isActive: !currentStatus });
      fetchUsers(pagination.page);
    } catch (err) {
      alert(`Failed to toggle user status: ${err.message}`);
    }
  };

  const handleDeleteClick = (user) => {
    setUserToDelete(user);
    setDeleteError(null);
  };

  const handleCancelDelete = () => {
    if (deleteLoading) return;
    setUserToDelete(null);
    setDeleteError(null);
  };

  const handleConfirmDelete = async () => {
    if (!userToDelete || deleteLoading) return;
    setDeleteLoading(true);
    setDeleteError(null);
    try {
      await deleteUser(userToDelete._id);
      setUserToDelete(null);
      fetchUsers(pagination.page);
    } catch (err) {
      setDeleteError(err.message || 'Failed to delete user account.');
    } finally {
      setDeleteLoading(false);
    }
  };

  // Keyboard accessibility: Escape key to dismiss delete modal
  useEffect(() => {
    if (!userToDelete) return;
    const handleKeyDown = (e) => {
      if (e.key === 'Escape' && !deleteLoading) {
        handleCancelDelete();
      }
    };
    window.addEventListener('keydown', handleKeyDown);
    return () => window.removeEventListener('keydown', handleKeyDown);
  }, [userToDelete, deleteLoading]);

  const handleCreateSubmit = async (e) => {
    e.preventDefault();
    setCreateSubmitting(true);
    setCreateError(null);
    try {
      await registerUser(newUser);
      setShowCreateModal(false);
      setNewUser({ username: '', email: '', password: '', role: 'VIEWER' });
      fetchUsers(1);
    } catch (err) {
      setCreateError(err.message || 'Failed to create user account.');
    } finally {
      setCreateSubmitting(false);
    }
  };

  return (
    <div>
      {/* Header */}
      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '1.5rem', flexWrap: 'wrap', gap: '1rem' }}>
        <div>
          <h2 style={{ fontSize: '1.35rem', fontWeight: 700, color: '#f8fafc', display: 'flex', alignItems: 'center', gap: '0.5rem' }}>
            <Users size={22} style={{ color: 'var(--accent-cyan)' }} />
            User Access & Role Management (Admin)
          </h2>
          <p style={{ fontSize: '0.825rem', color: 'var(--text-muted)', margin: '0.2rem 0 0 0' }}>
            Manage SOC platform user accounts, role-based access control, and active sessions
          </p>
        </div>

        <button onClick={() => setShowCreateModal(true)} className="btn btn-primary">
          <UserPlus size={16} />
          Create New User
        </button>
      </div>

      {error && <ErrorBanner message={error} onRetry={() => fetchUsers(pagination.page)} />}

      {/* Users Table Card */}
      <div className="soc-card">
        {loading ? (
          <LoadingSpinner message="Querying user database..." />
        ) : users.length === 0 ? (
          <div style={{ padding: '3rem 1.5rem', textAlign: 'center', color: 'var(--text-muted)' }}>
            <Users size={36} style={{ color: 'var(--border-color)', marginBottom: '0.75rem' }} />
            <p>No user accounts found.</p>
          </div>
        ) : (
          <div className="table-container">
            <table className="soc-table">
              <thead>
                <tr>
                  <th>Username</th>
                  <th>Email</th>
                  <th>Role</th>
                  <th>Status</th>
                  <th>Last Login</th>
                  <th>Created At</th>
                  <th>Actions</th>
                </tr>
              </thead>
              <tbody>
                {users.map((user) => (
                  <tr key={user._id}>
                    <td style={{ fontWeight: 600, color: '#f8fafc' }}>{user.username}</td>
                    <td style={{ fontFamily: 'var(--font-mono)', fontSize: '0.8rem' }}>{user.email}</td>
                    <td>
                      <select
                        value={user.role}
                        onChange={(e) => handleRoleChange(user._id, e.target.value)}
                        className="form-select"
                        style={{ padding: '0.25rem 0.5rem', fontSize: '0.775rem' }}
                      >
                        <option value="ADMIN">ADMIN</option>
                        <option value="ANALYST">ANALYST</option>
                        <option value="VIEWER">VIEWER</option>
                      </select>
                    </td>
                    <td>
                      <button
                        onClick={() => handleToggleActive(user._id, user.isActive)}
                        className="btn"
                        style={{
                          padding: '0.2rem 0.5rem',
                          fontSize: '0.725rem',
                          borderColor: user.isActive ? 'rgba(16,185,129,0.3)' : 'rgba(244,63,94,0.3)',
                          color: user.isActive ? '#34d399' : '#f87171'
                        }}
                      >
                        {user.isActive ? <CheckCircle size={12} /> : <XCircle size={12} />}
                        {user.isActive ? 'Active' : 'Disabled'}
                      </button>
                    </td>
                    <td style={{ fontFamily: 'var(--font-mono)', fontSize: '0.75rem', color: 'var(--text-muted)' }}>
                      {user.lastLoginAt ? new Date(user.lastLoginAt).toLocaleString() : 'Never'}
                    </td>
                    <td style={{ fontFamily: 'var(--font-mono)', fontSize: '0.75rem', color: 'var(--text-muted)' }}>
                      {new Date(user.createdAt).toLocaleDateString()}
                    </td>
                    <td>
                      <button
                        onClick={() => handleDeleteClick(user)}
                        className="btn"
                        aria-label={`Delete user ${user.username}`}
                        style={{ padding: '0.25rem 0.5rem', fontSize: '0.725rem', borderColor: 'rgba(244,63,94,0.4)', color: '#f87171' }}
                      >
                        <Trash2 size={12} /> Delete
                      </button>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </div>

      {/* Create User Modal */}
      {showCreateModal && (
        <div style={{
          position: 'fixed',
          inset: 0,
          background: 'rgba(5, 8, 15, 0.85)',
          backdropFilter: 'blur(8px)',
          display: 'flex',
          alignItems: 'center',
          justifyContent: 'center',
          zIndex: 1000,
          padding: '1rem'
        }}>
          <div className="soc-card" style={{ maxWidth: '460px', width: '100%', border: '1px solid var(--accent-cyan)' }}>
            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '1rem', borderBottom: '1px solid var(--border-color)', paddingBottom: '0.75rem' }}>
              <h3 style={{ fontSize: '1.1rem', fontWeight: 700, color: '#f8fafc', margin: 0 }}>
                Create New User Account
              </h3>
              <button onClick={() => setShowCreateModal(false)} style={{ background: 'none', border: 'none', color: 'var(--text-secondary)', cursor: 'pointer' }}>
                <X size={20} />
              </button>
            </div>

            {createError && (
              <div style={{ background: 'rgba(244, 63, 94, 0.15)', border: '1px solid rgba(244, 63, 94, 0.3)', padding: '0.75rem', borderRadius: '8px', color: '#f87171', fontSize: '0.825rem', marginBottom: '1rem' }}>
                {createError}
              </div>
            )}

            <form onSubmit={handleCreateSubmit}>
              <div className="form-group">
                <label className="form-label">Username:</label>
                <input
                  type="text"
                  required
                  value={newUser.username}
                  onChange={(e) => setNewUser({ ...newUser, username: e.target.value })}
                  className="form-input"
                />
              </div>

              <div className="form-group">
                <label className="form-label">Email Address:</label>
                <input
                  type="email"
                  required
                  value={newUser.email}
                  onChange={(e) => setNewUser({ ...newUser, email: e.target.value })}
                  className="form-input"
                />
              </div>

              <div className="form-group">
                <label className="form-label">Initial Password:</label>
                <input
                  type="password"
                  required
                  value={newUser.password}
                  onChange={(e) => setNewUser({ ...newUser, password: e.target.value })}
                  className="form-input"
                  placeholder="Min 8 chars with letters & numbers"
                />
              </div>

              <div className="form-group">
                <label className="form-label">Assigned Role:</label>
                <select
                  value={newUser.role}
                  onChange={(e) => setNewUser({ ...newUser, role: e.target.value })}
                  className="form-select"
                >
                  <option value="VIEWER">VIEWER (Read-Only)</option>
                  <option value="ANALYST">ANALYST (SOC Operations)</option>
                  <option value="ADMIN">ADMIN (Full Control)</option>
                </select>
              </div>

              <div style={{ display: 'flex', justifyContent: 'flex-end', gap: '0.75rem', marginTop: '1.25rem' }}>
                <button type="button" onClick={() => setShowCreateModal(false)} className="btn">Cancel</button>
                <button type="submit" disabled={createSubmitting} className="btn btn-primary">
                  {createSubmitting ? 'Creating...' : 'Create Account'}
                </button>
              </div>
            </form>
          </div>
        </div>
      )}

      {/* Custom Delete User Confirmation Modal */}
      {userToDelete && (
        <div
          className="modal-backdrop"
          style={{
            position: 'fixed',
            inset: 0,
            background: 'rgba(5, 8, 15, 0.85)',
            backdropFilter: 'blur(8px)',
            display: 'flex',
            alignItems: 'center',
            justifyContent: 'center',
            zIndex: 1050,
            padding: '1rem'
          }}
          onClick={(e) => {
            if (e.target === e.currentTarget && !deleteLoading) {
              handleCancelDelete();
            }
          }}
          role="presentation"
        >
          <div
            className="soc-card delete-confirmation-modal"
            role="dialog"
            aria-modal="true"
            aria-labelledby="delete-user-modal-title"
            aria-describedby="delete-user-modal-desc"
            style={{
              maxWidth: '450px',
              width: '100%',
              border: '1px solid rgba(244, 63, 94, 0.4)',
              boxShadow: '0 20px 40px rgba(0, 0, 0, 0.6), 0 0 25px rgba(244, 63, 94, 0.15)',
              padding: '1.75rem',
              position: 'relative'
            }}
          >
            <div style={{ display: 'flex', alignItems: 'flex-start', gap: '1rem', marginBottom: '1.25rem' }}>
              <div
                style={{
                  width: '42px',
                  height: '42px',
                  borderRadius: '10px',
                  background: 'rgba(244, 63, 94, 0.12)',
                  border: '1px solid rgba(244, 63, 94, 0.3)',
                  display: 'flex',
                  alignItems: 'center',
                  justifyContent: 'center',
                  color: '#f87171',
                  flexShrink: 0
                }}
              >
                <Trash2 size={22} />
              </div>
              <div style={{ flex: 1 }}>
                <h3
                  id="delete-user-modal-title"
                  style={{ fontSize: '1.15rem', fontWeight: 700, color: '#f8fafc', margin: '0 0 0.25rem 0' }}
                >
                  Delete User
                </h3>
                <p
                  id="delete-user-modal-desc"
                  style={{ fontSize: '0.85rem', color: 'var(--text-secondary)', margin: 0, lineHeight: 1.4 }}
                >
                  Are you sure you want to delete this user?
                </p>
              </div>
              <button
                type="button"
                onClick={handleCancelDelete}
                disabled={deleteLoading}
                aria-label="Close dialog"
                style={{
                  background: 'none',
                  border: 'none',
                  color: 'var(--text-muted)',
                  cursor: deleteLoading ? 'not-allowed' : 'pointer',
                  padding: '0.25rem',
                  display: 'flex',
                  alignItems: 'center',
                  justifyContent: 'center'
                }}
              >
                <X size={18} />
              </button>
            </div>

            {/* Selected User Details Box */}
            <div
              style={{
                background: 'rgba(15, 23, 42, 0.6)',
                border: '1px solid var(--border-color)',
                borderRadius: '8px',
                padding: '0.875rem 1rem',
                marginBottom: '1rem'
              }}
            >
              <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '0.35rem' }}>
                <span style={{ fontSize: '0.75rem', fontWeight: 600, color: 'var(--text-muted)', textTransform: 'uppercase' }}>
                  User Account
                </span>
                <span
                  className="badge"
                  style={{
                    fontSize: '0.7rem',
                    padding: '0.15rem 0.5rem',
                    background: 'rgba(51, 65, 85, 0.4)',
                    color: '#cbd5e1'
                  }}
                >
                  {userToDelete.role}
                </span>
              </div>
              <div style={{ fontSize: '1rem', fontWeight: 700, color: '#f8fafc', marginBottom: '0.25rem' }}>
                {userToDelete.username}
              </div>
              <div style={{ fontSize: '0.8rem', color: 'var(--text-secondary)', fontFamily: 'var(--font-mono)' }}>
                {userToDelete.email}
              </div>
            </div>

            <p style={{ fontSize: '0.8rem', color: '#f87171', margin: '0 0 1.25rem 0', display: 'flex', alignItems: 'center', gap: '0.4rem' }}>
              <span>⚠️</span> This action cannot be undone.
            </p>

            {deleteError && (
              <div
                role="alert"
                style={{
                  background: 'rgba(244, 63, 94, 0.15)',
                  border: '1px solid rgba(244, 63, 94, 0.3)',
                  padding: '0.65rem 0.85rem',
                  borderRadius: '8px',
                  color: '#f87171',
                  fontSize: '0.825rem',
                  marginBottom: '1.25rem'
                }}
              >
                {deleteError}
              </div>
            )}

            <div style={{ display: 'flex', justifyContent: 'flex-end', gap: '0.75rem' }}>
              <button
                type="button"
                onClick={handleCancelDelete}
                disabled={deleteLoading}
                className="btn"
                style={{ minWidth: '85px', justifyContent: 'center' }}
              >
                Cancel
              </button>
              <button
                type="button"
                onClick={handleConfirmDelete}
                disabled={deleteLoading}
                className="btn"
                style={{
                  minWidth: '120px',
                  justifyContent: 'center',
                  background: 'linear-gradient(135deg, #e11d48 0%, #f43f5e 100%)',
                  border: '1px solid rgba(244, 63, 94, 0.6)',
                  color: '#ffffff',
                  fontWeight: 600,
                  boxShadow: '0 0 12px rgba(244, 63, 94, 0.25)'
                }}
              >
                {deleteLoading ? (
                  <>
                    <Loader2 size={15} className="spin" />
                    <span>Deleting...</span>
                  </>
                ) : (
                  <>
                    <Trash2 size={15} />
                    <span>Delete User</span>
                  </>
                )}
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
};

export default UsersPage;

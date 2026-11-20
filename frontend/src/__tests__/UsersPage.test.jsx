import React from 'react';
import { render, screen, waitFor, fireEvent, within } from '@testing-library/react';
import { describe, test, expect, vi, beforeEach } from 'vitest';
import UsersPage from '../pages/UsersPage';
import * as authService from '../services/authService';

vi.mock('../services/authService');

describe('UsersPage Custom Delete Confirmation Modal Suite', () => {
  const mockUsers = [
    {
      _id: 'user_1',
      username: 'viewer_1787743123',
      email: 'viewer_1787743123@netshield.io',
      role: 'VIEWER',
      isActive: true,
      lastLoginAt: '2026-09-01T12:00:00Z',
      createdAt: '2026-08-15T08:30:00Z'
    },
    {
      _id: 'user_2',
      username: 'analyst_bob',
      email: 'analyst_bob@netshield.io',
      role: 'ANALYST',
      isActive: false,
      lastLoginAt: null,
      createdAt: '2026-08-20T10:00:00Z'
    }
  ];

  beforeEach(() => {
    vi.resetAllMocks();
    authService.getUsers.mockResolvedValue({
      data: mockUsers,
      pagination: { page: 1, limit: 20, total: 2, totalPages: 1 }
    });
  });

  test('1. Delete button renders for each user in the table', async () => {
    render(<UsersPage />);

    await waitFor(() => {
      expect(screen.getByText('viewer_1787743123')).toBeInTheDocument();
    });

    const deleteButtons = screen.getAllByRole('button', { name: /^delete user/i });
    expect(deleteButtons.length).toBe(2);
  });

  test('2. Clicking Delete opens custom in-app confirmation modal with role="dialog"', async () => {
    render(<UsersPage />);

    await waitFor(() => {
      expect(screen.getByText('viewer_1787743123')).toBeInTheDocument();
    });

    const deleteBtn = screen.getByRole('button', { name: 'Delete user viewer_1787743123' });
    fireEvent.click(deleteBtn);

    const dialog = screen.getByRole('dialog');
    expect(dialog).toBeInTheDocument();
    expect(dialog).toHaveAttribute('aria-modal', 'true');
    expect(dialog).toHaveAttribute('aria-labelledby', 'delete-user-modal-title');
    expect(dialog).toHaveAttribute('aria-describedby', 'delete-user-modal-desc');
  });

  test('3. Native window.confirm() is NEVER called when clicking Delete', async () => {
    const confirmSpy = vi.spyOn(window, 'confirm');
    render(<UsersPage />);

    await waitFor(() => {
      expect(screen.getByText('viewer_1787743123')).toBeInTheDocument();
    });

    const deleteBtn = screen.getByRole('button', { name: 'Delete user viewer_1787743123' });
    fireEvent.click(deleteBtn);

    expect(confirmSpy).not.toHaveBeenCalled();
    confirmSpy.mockRestore();
  });

  test('4. Modal dynamically displays the correct selected username, email, and role', async () => {
    render(<UsersPage />);

    await waitFor(() => {
      expect(screen.getByText('viewer_1787743123')).toBeInTheDocument();
    });

    const deleteBtn = screen.getByRole('button', { name: 'Delete user viewer_1787743123' });
    fireEvent.click(deleteBtn);

    const dialog = screen.getByRole('dialog');
    expect(dialog).toHaveTextContent('viewer_1787743123');
    expect(dialog).toHaveTextContent('viewer_1787743123@netshield.io');
    expect(dialog).toHaveTextContent('VIEWER');
    expect(dialog).toHaveTextContent(/This action cannot be undone/i);
  });

  test('5. Clicking Cancel closes modal without deleting user', async () => {
    render(<UsersPage />);

    await waitFor(() => {
      expect(screen.getByText('viewer_1787743123')).toBeInTheDocument();
    });

    fireEvent.click(screen.getByRole('button', { name: 'Delete user viewer_1787743123' }));
    const dialog = screen.getByRole('dialog');
    expect(dialog).toBeInTheDocument();

    const cancelBtn = within(dialog).getByRole('button', { name: /^cancel$/i });
    fireEvent.click(cancelBtn);

    expect(screen.queryByRole('dialog')).not.toBeInTheDocument();
    expect(authService.deleteUser).not.toHaveBeenCalled();
  });

  test('6. Pressing Escape key closes the modal without deleting user', async () => {
    render(<UsersPage />);

    await waitFor(() => {
      expect(screen.getByText('viewer_1787743123')).toBeInTheDocument();
    });

    fireEvent.click(screen.getByRole('button', { name: 'Delete user viewer_1787743123' }));
    expect(screen.getByRole('dialog')).toBeInTheDocument();

    fireEvent.keyDown(window, { key: 'Escape', code: 'Escape' });

    expect(screen.queryByRole('dialog')).not.toBeInTheDocument();
    expect(authService.deleteUser).not.toHaveBeenCalled();
  });

  test('7. Confirming deletion calls deleteUser API with correct userId and closes modal on success', async () => {
    authService.deleteUser.mockResolvedValueOnce({ success: true });
    render(<UsersPage />);

    await waitFor(() => {
      expect(screen.getByText('viewer_1787743123')).toBeInTheDocument();
    });

    fireEvent.click(screen.getByRole('button', { name: 'Delete user viewer_1787743123' }));

    const dialog = screen.getByRole('dialog');
    const confirmDeleteBtn = within(dialog).getByRole('button', { name: /^delete user$/i });
    fireEvent.click(confirmDeleteBtn);

    await waitFor(() => {
      expect(authService.deleteUser).toHaveBeenCalledTimes(1);
      expect(authService.deleteUser).toHaveBeenCalledWith('user_1');
    });

    await waitFor(() => {
      expect(screen.queryByRole('dialog')).not.toBeInTheDocument();
    });
  });

  test('8. Delete button is disabled and displays loading state while request is in progress', async () => {
    let resolveDelete;
    authService.deleteUser.mockImplementation(
      () =>
        new Promise((resolve) => {
          resolveDelete = resolve;
        })
    );

    render(<UsersPage />);

    await waitFor(() => {
      expect(screen.getByText('viewer_1787743123')).toBeInTheDocument();
    });

    fireEvent.click(screen.getByRole('button', { name: 'Delete user viewer_1787743123' }));

    const dialog = screen.getByRole('dialog');
    const confirmDeleteBtn = within(dialog).getByRole('button', { name: /^delete user$/i });
    fireEvent.click(confirmDeleteBtn);

    // During loading
    await waitFor(() => {
      expect(confirmDeleteBtn).toBeDisabled();
      expect(within(dialog).getByText(/Deleting.../i)).toBeInTheDocument();
    });

    // Resolve delete
    resolveDelete({ success: true });

    await waitFor(() => {
      expect(screen.queryByRole('dialog')).not.toBeInTheDocument();
    });
  });

  test('9. Failed deletion keeps dialog open, shows error message, and does not crash UI', async () => {
    authService.deleteUser.mockRejectedValueOnce(new Error('Cannot delete superadmin account.'));
    render(<UsersPage />);

    await waitFor(() => {
      expect(screen.getByText('viewer_1787743123')).toBeInTheDocument();
    });

    fireEvent.click(screen.getByRole('button', { name: 'Delete user viewer_1787743123' }));

    const dialog = screen.getByRole('dialog');
    const confirmDeleteBtn = within(dialog).getByRole('button', { name: /^delete user$/i });
    fireEvent.click(confirmDeleteBtn);

    await waitFor(() => {
      expect(within(dialog).getByRole('alert')).toHaveTextContent('Cannot delete superadmin account.');
      expect(screen.getByRole('dialog')).toBeInTheDocument();
    });

    // User row remains in the table
    expect(screen.getAllByText('viewer_1787743123').length).toBe(2);
  });

  test('10. Multiple rapid clicks on Delete User button do NOT create duplicate delete requests', async () => {
    let resolveDelete;
    authService.deleteUser.mockImplementation(
      () =>
        new Promise((resolve) => {
          resolveDelete = resolve;
        })
    );

    render(<UsersPage />);

    await waitFor(() => {
      expect(screen.getByText('viewer_1787743123')).toBeInTheDocument();
    });

    fireEvent.click(screen.getByRole('button', { name: 'Delete user viewer_1787743123' }));

    const dialog = screen.getByRole('dialog');
    const confirmDeleteBtn = within(dialog).getByRole('button', { name: /^delete user$/i });
    fireEvent.click(confirmDeleteBtn);
    fireEvent.click(confirmDeleteBtn);
    fireEvent.click(confirmDeleteBtn);

    expect(authService.deleteUser).toHaveBeenCalledTimes(1);

    resolveDelete({ success: true });
    await waitFor(() => {
      expect(screen.queryByRole('dialog')).not.toBeInTheDocument();
    });
  });
});

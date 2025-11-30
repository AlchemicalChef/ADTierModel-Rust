import { create } from "zustand";

export type NotificationType = "success" | "error" | "warning" | "info";

export interface Notification {
  id: string;
  type: NotificationType;
  title: string;
  message?: string;
  duration?: number; // ms, default 5000, 0 = permanent
  action?: {
    label: string;
    onClick: () => void;
  };
  createdAt: number;
}

interface NotificationState {
  notifications: Notification[];
  addNotification: (notification: Omit<Notification, "id" | "createdAt">) => string;
  removeNotification: (id: string) => void;
  clearAll: () => void;
}

let notificationId = 0;

export const useNotificationStore = create<NotificationState>((set) => ({
  notifications: [],

  addNotification: (notification) => {
    const id = `notification-${++notificationId}`;
    const newNotification: Notification = {
      ...notification,
      id,
      duration: notification.duration ?? 5000,
      createdAt: Date.now(),
    };

    set((state) => ({
      notifications: [...state.notifications, newNotification],
    }));

    // Auto-remove after duration (if not permanent)
    if (newNotification.duration && newNotification.duration > 0) {
      setTimeout(() => {
        set((state) => ({
          notifications: state.notifications.filter((n) => n.id !== id),
        }));
      }, newNotification.duration);
    }

    return id;
  },

  removeNotification: (id) => {
    set((state) => ({
      notifications: state.notifications.filter((n) => n.id !== id),
    }));
  },

  clearAll: () => {
    set({ notifications: [] });
  },
}));

// Helper functions for common notification types
export const notify = {
  success: (title: string, message?: string) =>
    useNotificationStore.getState().addNotification({ type: "success", title, message }),

  error: (title: string, message?: string) =>
    useNotificationStore.getState().addNotification({
      type: "error",
      title,
      message,
      duration: 8000, // Errors stay longer
    }),

  warning: (title: string, message?: string) =>
    useNotificationStore.getState().addNotification({
      type: "warning",
      title,
      message,
      duration: 6000,
    }),

  info: (title: string, message?: string) =>
    useNotificationStore.getState().addNotification({ type: "info", title, message }),

  critical: (title: string, message?: string, action?: Notification["action"]) =>
    useNotificationStore.getState().addNotification({
      type: "error",
      title,
      message,
      duration: 0, // Permanent until dismissed
      action,
    }),
};

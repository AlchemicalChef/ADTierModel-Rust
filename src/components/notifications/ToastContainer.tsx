import { Transition } from "@headlessui/react";
import {
  CheckCircleIcon,
  ExclamationTriangleIcon,
  XCircleIcon,
  InformationCircleIcon,
  XMarkIcon,
} from "@heroicons/react/24/outline";
import { useNotificationStore, type NotificationType } from "../../store/notificationStore";

const iconMap: Record<NotificationType, React.ElementType> = {
  success: CheckCircleIcon,
  error: XCircleIcon,
  warning: ExclamationTriangleIcon,
  info: InformationCircleIcon,
};

const colorMap: Record<NotificationType, { bg: string; icon: string; border: string }> = {
  success: {
    bg: "bg-green-50 dark:bg-green-900/20",
    icon: "text-green-500 dark:text-green-400",
    border: "border-green-200 dark:border-green-800",
  },
  error: {
    bg: "bg-red-50 dark:bg-red-900/20",
    icon: "text-red-500 dark:text-red-400",
    border: "border-red-200 dark:border-red-800",
  },
  warning: {
    bg: "bg-amber-50 dark:bg-amber-900/20",
    icon: "text-amber-500 dark:text-amber-400",
    border: "border-amber-200 dark:border-amber-800",
  },
  info: {
    bg: "bg-blue-50 dark:bg-blue-900/20",
    icon: "text-blue-500 dark:text-blue-400",
    border: "border-blue-200 dark:border-blue-800",
  },
};

export function ToastContainer() {
  const { notifications, removeNotification } = useNotificationStore();

  return (
    <div
      aria-live="polite"
      className="fixed bottom-4 right-4 z-50 flex flex-col gap-2 max-w-sm w-full pointer-events-none"
    >
      {notifications.map((notification) => {
        const Icon = iconMap[notification.type];
        const colors = colorMap[notification.type];

        return (
          <Transition
            key={notification.id}
            show={true}
            appear={true}
            enter="transform transition duration-300 ease-out"
            enterFrom="translate-x-full opacity-0"
            enterTo="translate-x-0 opacity-100"
            leave="transform transition duration-200 ease-in"
            leaveFrom="translate-x-0 opacity-100"
            leaveTo="translate-x-full opacity-0"
          >
            <div
              className={`pointer-events-auto rounded-lg border shadow-lg ${colors.bg} ${colors.border} p-4`}
            >
              <div className="flex items-start gap-3">
                <Icon className={`w-5 h-5 flex-shrink-0 mt-0.5 ${colors.icon}`} />
                <div className="flex-1 min-w-0">
                  <p className="text-sm font-medium text-gray-900 dark:text-gray-100">
                    {notification.title}
                  </p>
                  {notification.message && (
                    <p className="mt-1 text-sm text-gray-600 dark:text-gray-400">
                      {notification.message}
                    </p>
                  )}
                  {notification.action && (
                    <button
                      onClick={() => {
                        notification.action?.onClick();
                        removeNotification(notification.id);
                      }}
                      className="mt-2 text-sm font-medium text-blue-600 dark:text-blue-400 hover:text-blue-700 dark:hover:text-blue-300"
                    >
                      {notification.action.label}
                    </button>
                  )}
                </div>
                <button
                  onClick={() => removeNotification(notification.id)}
                  className="flex-shrink-0 p-1 text-gray-400 hover:text-gray-600 dark:hover:text-gray-300 rounded"
                >
                  <XMarkIcon className="w-4 h-4" />
                </button>
              </div>
            </div>
          </Transition>
        );
      })}
    </div>
  );
}

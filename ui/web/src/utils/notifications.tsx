import { createContext, useCallback, useContext, useState } from "react";
import Flashbar, { FlashbarProps } from "@cloudscape-design/components/flashbar";

type NotificationType = "error" | "warning" | "success" | "info";

interface NotificationContextType {
  addNotification: (type: NotificationType, content: string, header?: string) => void;
  clearNotifications: () => void;
  items: FlashbarProps.MessageDefinition[];
}

const NotificationContext = createContext<NotificationContextType>({
  addNotification: () => {},
  clearNotifications: () => {},
  items: [],
});

export function useNotifications() {
  return useContext(NotificationContext);
}

let _idCounter = 0;

export function NotificationProvider({ children }: { children: React.ReactNode }) {
  const [items, setItems] = useState<FlashbarProps.MessageDefinition[]>([]);

  const addNotification = useCallback((type: NotificationType, content: string, header?: string) => {
    const id = `notif-${++_idCounter}`;
    setItems((prev) => [
      ...prev,
      {
        id,
        type,
        content,
        header,
        dismissible: true,
        onDismiss: () => setItems((curr) => curr.filter((i) => i.id !== id)),
      },
    ]);
    // Scroll to top so the notification is visible
    window.scrollTo({ top: 0, behavior: "smooth" });
    // Log errors to the backend
    if (type === "error" || type === "warning") {
      fetch("/api/log-error", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ message: content, source: header || "UI" }),
      }).catch(() => {});
    }
  }, []);

  const clearNotifications = useCallback(() => {
    setItems([]);
  }, []);

  return (
    <NotificationContext.Provider value={{ addNotification, clearNotifications, items }}>
      {children}
    </NotificationContext.Provider>
  );
}

/** Render the Flashbar from notification context. Place in AppLayout notifications slot. */
export function NotificationBar() {
  const { items } = useNotifications();
  if (!items.length) return null;
  return <Flashbar items={items} />;
}

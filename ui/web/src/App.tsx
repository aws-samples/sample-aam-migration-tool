import { useState } from "react";
import AppLayout from "@cloudscape-design/components/app-layout";
import SideNavigation, { SideNavigationProps } from "@cloudscape-design/components/side-navigation";
import TopNavigation from "@cloudscape-design/components/top-navigation";
import PolicyAnalysis from "./pages/PolicyAnalysis";
import IamFederation from "./pages/IamFederation";
import Idc from "./pages/Idc";
import CacheManager from "./pages/CacheManager";
import { NotificationProvider, NotificationBar } from "./utils/notifications";

type PageId = "policy-analysis" | "iam-federation" | "idc" | "cache";

const LABELS: Record<PageId, string> = {
  "policy-analysis": "Policy Analysis",
  "iam-federation": "IAM Federation → AAM",
  idc: "IdC → AAM",
  cache: "Cache",
};

const NAV_ITEMS: SideNavigationProps.Item[] = [
  { type: "link", text: LABELS["iam-federation"], href: "#iam-federation" },
  {
    // Policy Analysis lives under the IdC → AAM flow: it is only required for
    // that migration use-case, so it is grouped beneath it rather than being a
    // standalone top-level tool.
    type: "expandable-link-group",
    text: LABELS.idc,
    href: "#idc",
    defaultExpanded: true,
    items: [{ type: "link", text: LABELS["policy-analysis"], href: "#policy-analysis" }],
  },
  { type: "divider" },
  { type: "link", text: LABELS.cache, href: "#cache" },
];

// Keep every page mounted and toggle visibility instead of unmounting on tab
// switch. This preserves each tab's state (form inputs, selections, a running
// scan's live polling) rather than discarding it every time the user navigates.
function Pane({ visible, children }: { visible: boolean; children: React.ReactNode }) {
  return <div style={{ display: visible ? "block" : "none" }}>{children}</div>;
}

export default function App() {
  const [active, setActive] = useState<PageId>("idc");

  return (
    <NotificationProvider>
      <TopNavigation
        identity={{ href: "#", title: "AAM Migration Tool Console" }}
        utilities={[{ type: "button", text: "Local mode", iconName: "status-info" }]}
      />
      <AppLayout
        toolsHide
        notifications={<NotificationBar />}
        navigation={
          <SideNavigation
            activeHref={`#${active}`}
            header={{ href: "#", text: "Migration tools" }}
            onFollow={(e) => {
              e.preventDefault();
              const id = e.detail.href.replace("#", "") as PageId;
              if (LABELS[id]) setActive(id);
            }}
            items={NAV_ITEMS}
          />
        }
        content={
          <>
            <Pane visible={active === "policy-analysis"}>
              <PolicyAnalysis />
            </Pane>
            <Pane visible={active === "iam-federation"}>
              <IamFederation />
            </Pane>
            <Pane visible={active === "idc"}>
              <Idc />
            </Pane>
            <Pane visible={active === "cache"}>
              {/* Refresh when shown so cache age/size reflect recent scans. */}
              <CacheManager active={active === "cache"} />
            </Pane>
          </>
        }
      />
    </NotificationProvider>
  );
}

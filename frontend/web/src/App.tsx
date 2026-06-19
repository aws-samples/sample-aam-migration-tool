import { useState } from "react";
import AppLayout from "@cloudscape-design/components/app-layout";
import SideNavigation, { SideNavigationProps } from "@cloudscape-design/components/side-navigation";
import TopNavigation from "@cloudscape-design/components/top-navigation";
import PolicyAnalysis from "./pages/PolicyAnalysis";
import IamFederation from "./pages/IamFederation";
import Idc from "./pages/Idc";
import CacheManager from "./pages/CacheManager";

type PageId = "policy-analysis" | "iam-federation" | "idc" | "cache";

const PAGES: Record<PageId, { label: string; render: () => JSX.Element }> = {
  "policy-analysis": { label: "Policy Analysis", render: () => <PolicyAnalysis /> },
  "iam-federation": { label: "IAM Federation → AAM", render: () => <IamFederation /> },
  idc: { label: "IdC → AAM", render: () => <Idc /> },
  cache: { label: "Cache", render: () => <CacheManager /> },
};

const NAV_ITEMS: SideNavigationProps.Item[] = [
  { type: "link", text: PAGES["policy-analysis"].label, href: "#policy-analysis" },
  { type: "link", text: PAGES["iam-federation"].label, href: "#iam-federation" },
  { type: "link", text: PAGES.idc.label, href: "#idc" },
  { type: "divider" },
  { type: "link", text: PAGES.cache.label, href: "#cache" },
];

export default function App() {
  const [active, setActive] = useState<PageId>("policy-analysis");

  return (
    <>
      <TopNavigation
        identity={{ href: "#", title: "Truffle — AAM Migration Console" }}
        utilities={[
          {
            type: "button",
            text: "Local mode",
            iconName: "status-info",
          },
        ]}
      />
      <AppLayout
        toolsHide
        navigation={
          <SideNavigation
            activeHref={`#${active}`}
            header={{ href: "#", text: "Migration tools" }}
            onFollow={(e) => {
              e.preventDefault();
              const id = e.detail.href.replace("#", "") as PageId;
              if (PAGES[id]) setActive(id);
            }}
            items={NAV_ITEMS}
          />
        }
        content={PAGES[active].render()}
      />
    </>
  );
}

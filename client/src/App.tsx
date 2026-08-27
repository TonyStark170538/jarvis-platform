import { useEffect } from "react";
import { Toaster } from "@/components/ui/sonner";
import { TooltipProvider } from "@/components/ui/tooltip";
import NotFound from "@/pages/NotFound";
import { Route, Switch } from "wouter";
import ErrorBoundary from "./components/ErrorBoundary";
import { ThemeProvider } from "./contexts/ThemeContext";
import Dashboard from "./pages/Dashboard";
import AttackLab from "./pages/AttackLab";
import Monitoring from "./pages/Monitoring";
import Incidents from "./pages/Incidents";
import Assets from "./pages/Assets";
import Reports from "./pages/Reports";
import Intelligence from "./pages/Intelligence";
import IocInvestigation from "./pages/IocInvestigation";
import Settings from "./pages/Settings";
import { securityStore } from "./security/securityStore";

function Router() {
  return (
    <Switch>
      <Route path={"/"} component={Dashboard} />
      <Route path={"/attack-lab"} component={AttackLab} />
      <Route path={"/monitoring"} component={Monitoring} />
      <Route path={"/incidents"} component={Incidents} />
      <Route path={"/assets"} component={Assets} />
      <Route path={"/reports"} component={Reports} />
      <Route path={"/intelligence"} component={Intelligence} />
      <Route path={"/intelligence/ioc/:id"} component={IocInvestigation} />
      <Route path={"/settings"} component={Settings} />
      <Route path={"/404"} component={NotFound} />
      <Route component={NotFound} />
    </Switch>
  );
}

function App() {
  useEffect(() => {
    securityStore.startBackendPolling();

    return () => {
      securityStore.stopBackendPolling();
    };
  }, []);

  return (
    <ErrorBoundary>
      <ThemeProvider defaultTheme="dark" switchable>
        <TooltipProvider>
          <Toaster />
          <Router />
        </TooltipProvider>
      </ThemeProvider>
    </ErrorBoundary>
  );
}

export default App;

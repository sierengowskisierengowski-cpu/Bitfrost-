import { useCallback, useEffect, useRef, useState } from "react";
import { Switch, Route, Router as WouterRouter, Redirect } from "wouter";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { AnimatePresence } from "framer-motion";
import { Toaster } from "@/components/ui/toaster";
import { TooltipProvider } from "@/components/ui/tooltip";

import { guardian, useSettings } from "@/lib/api";
import { isSetupComplete } from "@/lib/app-state";
import { startGuardian, stopGuardian } from "@/lib/tauri";

import { Splash } from "@/components/Splash";
import { Login } from "@/components/Login";
import { SetupWizard } from "@/components/SetupWizard";
import { Screensaver } from "@/components/Screensaver";
import { AppShell } from "@/components/AppShell";

import Overview from "@/pages/Overview";
import Incidents from "@/pages/Incidents";
import Attackers from "@/pages/Attackers";
import Live from "@/pages/Live";
import Timeline from "@/pages/Timeline";
import Mitre from "@/pages/Mitre";
import Settings from "@/pages/Settings";
import Legal from "@/pages/Legal";
import NotFound from "@/pages/not-found";

const queryClient = new QueryClient();

type Phase = "splash" | "wizard" | "login" | "app";

function Routes() {
  return (
    <AppShell>
      <Switch>
        <Route path="/" component={Overview} />
        <Route path="/overview" component={Overview} />
        <Route path="/incidents" component={Incidents} />
        <Route path="/attackers" component={Attackers} />
        <Route path="/live" component={Live} />
        <Route path="/timeline" component={Timeline} />
        <Route path="/mitre" component={Mitre} />
        <Route path="/settings" component={Settings} />
        <Route path="/legal" component={Legal} />
        <Route path="/not-found" component={NotFound} />
        <Route><Redirect to="/" /></Route>
      </Switch>
    </AppShell>
  );
}

function App() {
  const [phase, setPhase] = useState<Phase>("splash");
  const [idle, setIdle] = useState(false);
  const settings = useSettings();
  const idleTimer = useRef<ReturnType<typeof setTimeout> | null>(null);

  // start the guardian client (and, in desktop, the python guardian process)
  useEffect(() => {
    guardian.start();
    startGuardian();
    return () => {
      stopGuardian();
    };
  }, []);

  const onSplashDone = useCallback(() => {
    setPhase(isSetupComplete() ? "login" : "wizard");
  }, []);

  // inactivity -> screensaver, only while in the app
  const resetIdle = useCallback(() => {
    setIdle(false);
    if (idleTimer.current) clearTimeout(idleTimer.current);
    if (phase === "app") {
      idleTimer.current = setTimeout(() => setIdle(true), settings.screensaverMs);
    }
  }, [phase, settings.screensaverMs]);

  useEffect(() => {
    if (phase !== "app") {
      if (idleTimer.current) clearTimeout(idleTimer.current);
      return;
    }
    const events = ["mousemove", "mousedown", "keydown", "scroll", "touchstart"];
    events.forEach((e) => window.addEventListener(e, resetIdle));
    resetIdle();
    return () => {
      events.forEach((e) => window.removeEventListener(e, resetIdle));
      if (idleTimer.current) clearTimeout(idleTimer.current);
    };
  }, [phase, resetIdle]);

  const wake = useCallback(() => {
    setIdle(false);
    setPhase("login"); // re-authenticate after screensaver
  }, []);

  return (
    <QueryClientProvider client={queryClient}>
      <TooltipProvider>
        <WouterRouter base="">
          {phase === "splash" && <Splash onDone={onSplashDone} />}
          {phase === "wizard" && <SetupWizard onComplete={() => setPhase("login")} />}
          {phase === "login" && <Login onSuccess={() => setPhase("app")} />}
          {phase === "app" && <Routes />}
          <AnimatePresence>{idle && phase === "app" && <Screensaver onWake={wake} />}</AnimatePresence>
        </WouterRouter>
        <Toaster />
      </TooltipProvider>
    </QueryClientProvider>
  );
}

export default App;

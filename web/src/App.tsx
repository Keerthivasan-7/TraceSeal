import { Shell } from "./components/Shell";
import { CommandCenter } from "./screens/CommandCenter";
import { Identity } from "./screens/Identity";
import { Ledger } from "./screens/Ledger";
import { useConsoleStore } from "./store";

export function App() {
  const screen = useConsoleStore((state) => state.screen);
  return <Shell>
    {screen === "command" && <CommandCenter />}
    {screen === "identity" && <Identity />}
    {screen === "ledger" && <Ledger />}
  </Shell>;
}

import { Shell } from "./components/Shell";
import { CommandCenter } from "./screens/CommandCenter";
import { Distribute } from "./screens/Distribute";
import { Identity } from "./screens/Identity";
import { Inbox } from "./screens/Inbox";
import { Ledger } from "./screens/Ledger";
import { useConsoleStore } from "./store";

export function App() {
  const screen = useConsoleStore((state) => state.screen);
  return <Shell>
    {screen === "command" && <CommandCenter />}
    {screen === "identity" && <Identity />}
    {screen === "distribute" && <Distribute />}
    {screen === "inbox" && <Inbox />}
    {screen === "ledger" && <Ledger />}
  </Shell>;
}

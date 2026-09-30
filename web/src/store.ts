import { create } from "zustand";

export type Screen = "command" | "identity" | "distribute" | "inbox" | "ledger";

interface ConsoleState {
  screen: Screen;
  selectedProof: string | null;
  setScreen: (screen: Screen) => void;
  setSelectedProof: (txId: string | null) => void;
}

export const useConsoleStore = create<ConsoleState>((set) => ({
  screen: "command",
  selectedProof: null,
  setScreen: (screen) => set({ screen }),
  setSelectedProof: (selectedProof) => set({ selectedProof }),
}));

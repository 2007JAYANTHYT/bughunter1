import { create } from 'zustand'
import { persist } from 'zustand/middleware'

export interface Program {
  id: number
  name: string
  platform: string
  handle: string
  enabled: boolean
  auth_type: string
  auth_env_var: string
  scope_file: string
  policy_file: string
  custom_headers: string[]
  notifications: Record<string, any>
  created_at: string
  updated_at: string
}

interface ProgramState {
  programs: Program[]
  currentProgram: Program | null
  currentProgramId: number | null
  isLoading: boolean
  error: string | null

  // Actions
  fetchPrograms: () => Promise<void>
  createProgram: (program: Omit<Program, 'id' | 'created_at' | 'updated_at'>) => Promise<Program>
  updateProgram: (id: number, updates: Partial<Program>) => Promise<void>
  deleteProgram: (id: number) => Promise<void>
  setCurrentProgram: (program: Program | null) => void
  setCurrentProgramId: (id: number | null) => void
}

export const useProgramStore = create<ProgramState>()(
  persist(
    (set, get) => ({
      programs: [],
      currentProgram: null,
      currentProgramId: null,
      isLoading: false,
      error: null,

      fetchPrograms: async () => {
        set({ isLoading: true, error: null })
        try {
          const response = await fetch('/api/programs')
          if (!response.ok) throw new Error('Failed to fetch programs')
          const programs = await response.json()
          set({ programs, isLoading: false })
        } catch (error) {
          set({ error: (error as Error).message, isLoading: false })
        }
      },

      createProgram: async (programData) => {
        const response = await fetch('/api/programs', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify(programData),
        })
        if (!response.ok) throw new Error('Failed to create program')
        const program = await response.json()

        set((state) => ({
          programs: [...state.programs, program],
          currentProgram: program,
          currentProgramId: program.id,
        }))

        return program
      },

      updateProgram: async (id, updates) => {
        const response = await fetch(`/api/programs/${id}`, {
          method: 'PUT',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify(updates),
        })
        if (!response.ok) throw new Error('Failed to update program')

        set((state) => ({
          programs: state.programs.map((p) => (p.id === id ? { ...p, ...updates } : p)),
          currentProgram: state.currentProgram?.id === id ? { ...state.currentProgram, ...updates } : state.currentProgram,
        }))
      },

      deleteProgram: async (id) => {
        const response = await fetch(`/api/programs/${id}`, { method: 'DELETE' })
        if (!response.ok) throw new Error('Failed to delete program')

        set((state) => ({
          programs: state.programs.filter((p) => p.id !== id),
          currentProgram: state.currentProgram?.id === id ? null : state.currentProgram,
          currentProgramId: state.currentProgramId === id ? null : state.currentProgramId,
        }))
      },

      setCurrentProgram: (program) => {
        set({ currentProgram: program, currentProgramId: program?.id ?? null })
      },

      setCurrentProgramId: (id) => {
        const program = get().programs.find((p) => p.id === id) ?? null
        set({ currentProgram: program, currentProgramId: id })
      },
    }),
    {
      name: 'program-store',
      partialize: (state) => ({
        currentProgramId: state.currentProgramId,
      }),
    }
  )
)
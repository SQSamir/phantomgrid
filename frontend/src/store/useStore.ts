import { create } from 'zustand'

type S = { tenantId: string; setTenantId: (v:string)=>void }

export const useStore = create<S>((set) => ({
  tenantId: 'default',
  setTenantId: (tenantId) => set({ tenantId })
}))

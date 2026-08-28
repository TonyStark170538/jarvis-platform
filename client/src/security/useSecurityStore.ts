import { useEffect, useState } from 'react';
import type { SecurityStore } from './securityStore';
export function useSecurityStore(store: SecurityStore) { const [snapshot,setSnapshot]=useState(store.getSnapshot()); useEffect(()=>store.subscribe(setSnapshot),[store]); return snapshot; }

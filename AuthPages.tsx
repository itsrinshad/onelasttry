import { ChangeEvent, ReactNode, useState } from 'react'
import { Link, useNavigate } from 'react-router-dom'
import { supabase, toEmail } from './lib'
import { loginWith } from './auth'
import { Logo } from './Symbiote'

function Shell({ tab, children }: { tab: 'signup' | 'login' | 'admin'; children: ReactNode }) {
  return (
    <div className="max-w-sm mx-auto">
      <div className="text-center mb-4 sym-title"><Logo size={26} /></div>
      <div className="tabs">
        <Link to="/signup" className={'tab' + (tab === 'signup' ? ' on' : '')}>Sign up</Link>
        <Link to="/login" className={'tab' + (tab === 'login' ? ' on' : '')}>Login</Link>
        <Link to="/admin-login" className={'tab' + (tab === 'admin' ? ' on' : '')}>Admin</Link>
      </div>
      <div className="glass p-6">{children}</div>
    </div>
  )
}

export function Signup() {
  const [f, setF] = useState({ username: '', ff_uid: '', ff_ign: '', pw: '', pw2: '' })
  const [msg, setMsg] = useState(''); const [done, setDone] = useState(false); const [busy, setBusy] = useState(false)
  const set = (k: string) => (e: ChangeEvent<HTMLInputElement>) => setF({ ...f, [k]: e.target.value })
  const submit = async () => {
    setMsg('')
    const u = f.username.trim().toLowerCase()
    if (!/^[a-z0-9_]{3,24}$/.test(u)) return setMsg('Username: 3-24 letters, numbers or _ (no spaces).')
    if (!f.ff_uid.trim()) return setMsg('Enter your game ID.')
    if (f.pw.length < 6) return setMsg('Password must be at least 6 characters.')
    if (f.pw !== f.pw2) return setMsg('Passwords do not match.')
    setBusy(true)
    const free = await supabase.rpc('username_available', { p: u })
    if (free.data === false) { setBusy(false); return setMsg('That username is taken. Pick another.') }
    const { error } = await supabase.auth.signUp({ email: toEmail(u), password: f.pw, options: { data: { username: u, ff_uid: f.ff_uid.trim(), ff_ign: f.ff_ign.trim() || u } } })
    if (error) { setBusy(false); return setMsg(error.message) }
    await supabase.auth.signOut()
    setBusy(false); setDone(true)
  }
  if (done) return (
    <Shell tab="signup">
      <h2 className="text-xl font-bold mb-2">Request sent ✅</h2>
      <p className="text-sm text-gray-300">An admin will review your request. Once approved you can log in with your username and password. No email verification needed.</p>
      <Link to="/login" className="sym-btn inline-block mt-4">Go to Login</Link>
    </Shell>
  )
  return (
    <Shell tab="signup">
      <h2 className="text-xl font-bold mb-3">Join SYMBIOTES</h2>
      <input className="sym-inp" placeholder="Username" value={f.username} onChange={set('username')} autoCapitalize="none" />
      <input className="sym-inp" placeholder="Game ID (UID)" value={f.ff_uid} onChange={set('ff_uid')} inputMode="numeric" />
      <input className="sym-inp" placeholder="In-game name (optional)" value={f.ff_ign} onChange={set('ff_ign')} />
      <input className="sym-inp" type="password" placeholder="Password (min 6)" value={f.pw} onChange={set('pw')} />
      <input className="sym-inp" type="password" placeholder="Confirm password" value={f.pw2} onChange={set('pw2')} />
      <button className="sym-btn w-full" onClick={submit} disabled={busy}>{busy ? 'Sending…' : 'Send join request'}</button>
      {msg && <p className="mt-3 text-amber-300 text-sm">{msg}</p>}
      <p className="mt-3 text-xs text-gray-400">An admin must approve you before you can log in.</p>
    </Shell>
  )
}

function LoginForm({ admin }: { admin: boolean }) {
  const nav = useNavigate(); const [u, setU] = useState(''); const [pw, setPw] = useState(''); const [msg, setMsg] = useState(''); const [busy, setBusy] = useState(false)
  const go = async () => {
    setMsg(''); setBusy(true)
    const err = await loginWith(u, pw, admin)
    setBusy(false)
    if (err) return setMsg(err)
    nav(admin ? '/admin' : '/')
  }
  return (
    <Shell tab={admin ? 'admin' : 'login'}>
      <h2 className="text-xl font-bold mb-3">{admin ? 'Admin login' : 'Member login'}</h2>
      <input className="sym-inp" placeholder="Username" value={u} onChange={e => setU(e.target.value)} autoCapitalize="none" />
      <input className="sym-inp" type="password" placeholder="Password" value={pw} onChange={e => setPw(e.target.value)} onKeyDown={e => e.key === 'Enter' && go()} />
      <button className="sym-btn w-full" onClick={go} disabled={busy}>{busy ? 'Entering…' : 'Login'}</button>
      {msg && <p className="mt-3 text-amber-300 text-sm">{msg}</p>}
      {!admin && <p className="mt-3 text-xs text-gray-400">Forgot your password? Ask an admin to set a new one for you.</p>}
    </Shell>
  )
}
export const Login = () => <LoginForm admin={false} />
export const AdminLogin = () => <LoginForm admin />

import { useState } from "react"
import "./style.css"

const Section = ({ title, icon, children }) => (
  <div className="mb-3 rounded-xl border border-white/10 bg-white/5 overflow-hidden">
    <div className="flex items-center gap-2 px-4 py-2.5 border-b border-white/10 bg-white/5">
      <span className="text-base">{icon}</span>
      <span className="text-xs font-semibold tracking-widest uppercase text-zinc-400">{title}</span>
    </div>
    <div className="px-4 py-3 space-y-2">{children}</div>
  </div>
)

const Row = ({ label, value }) => (
  <div className="flex justify-between items-start gap-4">
    <span className="text-xs text-zinc-500 shrink-0 pt-0.5">{label}</span>
    <span className="text-xs text-zinc-200 text-right break-all">{value || <span className="text-zinc-600">—</span>}</span>
  </div>
)

export default function Popup() {
  const [domain, setDomain] = useState("")
  const [data, setData] = useState(null)
  const [loading, setLoading] = useState(false)
  const [error, setError] = useState(null)

  const lookup = async () => {
    if (!domain.trim()) return
    setLoading(true)
    setData(null)
    setError(null)
    try {
      const res = await fetch("https://digdog.onrender.com/lookup", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ domain: domain.trim() })
      })
      if (!res.ok) throw new Error("Server error")
      const json = await res.json()
      setData(json)
    } catch (e) {
      setError("Failed to reach server. Is FastAPI running?")
    } finally {
      setLoading(false)
    }
  }

  const handleKey = (e) => e.key === "Enter" && lookup()

  return (
    <div
      className="w-[400px] min-h-[200px] max-h-[600px] overflow-y-auto bg-[#0e0e12] text-white"
      style={{ fontFamily: "'DM Mono', 'Fira Code', monospace" }}
    >
      <div className="px-5 pt-5 pb-4 border-b border-white/10">
        <div className="flex items-center gap-2 mb-1">
          <span className="text-lg">🐕</span>
          <h1 className="text-sm font-bold tracking-widest uppercase text-white">DigDog</h1>
        </div>
        <p className="text-xs text-zinc-500">Domain intelligence lookup</p>
      </div>

      <div className="px-5 py-4">
        <div className="flex gap-2">
          <input
            className="flex-1 bg-white/5 border border-white/10 rounded-lg px-3 py-2 text-xs text-zinc-200 placeholder-zinc-600 outline-none focus:border-indigo-500 focus:ring-1 focus:ring-indigo-500/30 transition-all"
            placeholder="example.com"
            value={domain}
            onChange={(e) => setDomain(e.target.value)}
            onKeyDown={handleKey}
          />
          <button
            onClick={lookup}
            disabled={loading}
            className="px-4 py-2 bg-indigo-600 hover:bg-indigo-500 disabled:opacity-40 disabled:cursor-not-allowed text-white text-xs font-semibold rounded-lg transition-all tracking-wider"
          >
            {loading ? "..." : "DIG"}
          </button>
        </div>
        {error && <p className="mt-2 text-xs text-red-400">{error}</p>}
      </div>

      {data && (
        <div className="px-5 pb-5 space-y-1">

          {data.dns && (
            <Section title="DNS" icon="🌐">
              <Row label="IP Address" value={data.dns.ip} />
            </Section>
          )}

          {data.ip && Object.keys(data.ip).length > 0 && (
            <Section title="IP Info" icon="📍">
              <Row label="Country" value={data.ip.country} />
              <Row label="City" value={data.ip.city} />
              <Row label="ISP" value={data.ip.isp} />
              <Row label="Coordinates" value={data.ip.lat && `${data.ip.lat}, ${data.ip.lon}`} />
            </Section>
          )}

          {data.whois && (
            <Section title="WHOIS" icon="📋">
              <Row label="Registrar" value={data.whois.registrar} />
              <Row label="Registered" value={data.whois.registered?.split("T")[0]} />
              <Row label="Expires" value={data.whois.expiry?.split("T")[0]} />
              <Row label="Updated" value={data.whois.updated?.split("T")[0]} />
            </Section>
          )}

          {data.server && (
            <Section title="Server" icon="🖥️">
              <Row label="Server" value={data.server.server} />
              <Row label="Powered By" value={data.server.powered_by} />
              <Row label="CDN" value={data.server.cdn} />
            </Section>
          )}

        </div>
      )}

      {!data && !loading && (
        <div className="px-5 pb-6 text-center text-xs text-zinc-600">
          Enter a domain and press DIG
        </div>
      )}
    </div>
  )
}
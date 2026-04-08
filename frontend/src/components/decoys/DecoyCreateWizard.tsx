import { useMemo, useState } from 'react'
import { useForm } from 'react-hook-form'
import { z } from 'zod'
import { zodResolver } from '@hookform/resolvers/zod'
import { apiPost } from '../../api/client'

const decoyTypes = [
  { category: 'Network Services', key: 'http_honeypot', name: 'HTTP', desc: 'Fake web services', tags: ['http', 'web'] },
  { category: 'Remote Access', key: 'ssh_honeypot', name: 'SSH', desc: 'Interactive shell trap', tags: ['ssh', 'linux'] },
  { category: 'Database', key: 'mysql_honeypot', name: 'MySQL', desc: 'Fake MySQL endpoint', tags: ['mysql', 'db'] },
  { category: 'Cloud', key: 'aws_metadata_honeypot', name: 'AWS Metadata', desc: 'IMDS trap', tags: ['aws', 'metadata'] },
  { category: 'Files & Tokens', key: 'fake_file', name: 'Honey Document', desc: 'Beaconing fake files', tags: ['pdf', 'token'] },
]

const schema = z.object({
  name: z.string().min(3),
  type: z.string().min(1),
  ip_address: z.string().min(3),
  port: z.number().int().min(1).max(65535),
  banner: z.string().optional(),
  fake_hostname: z.string().optional(),
  os_fingerprint: z.string().optional(),
  server_header: z.string().optional(),
  template: z.string().optional(),
  capture_forms: z.boolean().optional(),
})

type FormData = z.infer<typeof schema>

export default function DecoyCreateWizard() {
  const [step, setStep] = useState(1)
  const [status, setStatus] = useState<string>('')
  const [decoyId, setDecoyId] = useState<string>('')

  const { register, watch, handleSubmit, setValue, formState: { errors } } = useForm<FormData>({
    resolver: zodResolver(schema),
    defaultValues: { port: 22, capture_forms: true },
  })

  const selectedType = watch('type')
  const grouped = useMemo(() => decoyTypes.reduce<Record<string, typeof decoyTypes>>((acc, t) => {
    acc[t.category] = acc[t.category] || []
    acc[t.category].push(t)
    return acc
  }, {}), [])

  const submit = async (deploy: boolean) => {
    const values = watch()
    const payload = {
      name: values.name,
      type: values.type,
      ip_address: values.ip_address,
      port: values.port,
      config: {
        banner: values.banner,
        fake_hostname: values.fake_hostname,
        os_fingerprint: values.os_fingerprint,
        server_header: values.server_header,
        template: values.template,
        capture_forms: values.capture_forms,
      },
      status: deploy ? 'deploying' : 'draft',
    }

    const decoy = await apiPost('/decoys', payload)
    setDecoyId(decoy?.id)
    if (deploy && decoy?.id) {
      await apiPost(`/decoys/${decoy.id}/deploy`, {})
      setStatus('Deploying...')
      const timer = setInterval(async () => {
        try {
          const s = await fetch(`/api/v1/decoys/${decoy.id}`).then(r => r.json())
          setStatus(`Status: ${s.status}`)
          if (['active', 'error'].includes(s.status)) clearInterval(timer)
        } catch {
          clearInterval(timer)
        }
      }, 2000)
    }
  }

  return (
    <div style={{ display: 'grid', gap: 12 }}>
      <h2>Create Decoy Wizard</h2>
      <div>Step {step}/3</div>

      {step === 1 && (
        <div style={{ display: 'grid', gap: 12 }}>
          {Object.entries(grouped).map(([cat, items]) => (
            <div key={cat}>
              <h4>{cat}</h4>
              <div style={{ display: 'grid', gridTemplateColumns: 'repeat(3, minmax(180px, 1fr))', gap: 8 }}>
                {items.map(item => (
                  <button key={item.key} onClick={() => { setValue('type', item.key); setStep(2) }} style={{ textAlign: 'left', border: selectedType === item.key ? '1px solid #60a5fa' : '1px solid #1f2937', background: '#111827', borderRadius: 8, padding: 10 }}>
                    <strong>{item.name}</strong>
                    <div>{item.desc}</div>
                    <small>{item.tags.join(', ')}</small>
                  </button>
                ))}
              </div>
            </div>
          ))}
        </div>
      )}

      {step === 2 && (
        <form onSubmit={handleSubmit(() => setStep(3))} style={{ display: 'grid', gap: 8 }}>
          <input placeholder='Decoy name' {...register('name')} />
          <input placeholder='IP address' {...register('ip_address')} />
          <input type='number' placeholder='Port' {...register('port', { valueAsNumber: true })} />

          {selectedType.includes('ssh') && <>
            <input placeholder='Banner' {...register('banner')} />
            <input placeholder='Hostname' {...register('fake_hostname')} />
            <input placeholder='OS fingerprint' {...register('os_fingerprint')} />
          </>}

          {selectedType.includes('http') && <>
            <input placeholder='Server header' {...register('server_header')} />
            <input placeholder='Template (apache_default, wordpress...)' {...register('template')} />
            <label><input type='checkbox' {...register('capture_forms')} /> capture forms</label>
          </>}

          {Object.keys(errors).length > 0 && <div style={{ color: '#f87171' }}>Please fix validation errors.</div>}
          <button type='submit'>Continue</button>
        </form>
      )}

      {step === 3 && (
        <div style={{ display: 'grid', gap: 8 }}>
          <h4>Review</h4>
          <pre style={{ background: '#0b1220', padding: 10 }}>{JSON.stringify(watch(), null, 2)}</pre>
          <div style={{ display: 'flex', gap: 8 }}>
            <button onClick={() => submit(true)}>Deploy Now</button>
            <button onClick={() => submit(false)}>Save Draft</button>
            <button onClick={() => setStep(2)}>Back</button>
          </div>
          {status && <div>{status}</div>}
          {decoyId && <div>Decoy ID: {decoyId}</div>}
        </div>
      )}
    </div>
  )
}

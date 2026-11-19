import React, { useEffect, useState } from 'react';
import { createRoot } from 'react-dom/client';
import './styles.css';

const api = async (path, options = {}) => {
  const {
    admin = false,
    ...fetchOptions
  } = options;

  const headers = new Headers(
    fetchOptions.headers || {}
  );

  const response = await fetch(
    `/api/v1${path}`,
    {
      ...fetchOptions,
      headers,
      credentials: 'include'
    }
  );

  const data = await response
    .json()
    .catch(() => ({}));

  if (!response.ok) {
    if (response.status === 401 && admin) {
      window.dispatchEvent(new Event('quantumproof:session-expired'));
    }

    throw new Error(
      data.detail ||
      'The request could not be completed.'
    );
  }

  return data;
};


const REGISTRY_PAGE_SIZE = 20;


function Icon({ name }) {
  const icons = {
    shield: '◈',
    upload: '↑',
    search: '⌕',
    check: '✓',
    lock: '⌑',
    ledger: '▤',
    arrow: '→',
    refresh: '↻',
    file: '□',
    clock: '◷',
    key: '⚿',
  };

  return (
    <span
      className={`icon icon-${name}`}
      aria-hidden="true"
    >
      {icons[name] || '•'}
    </span>
  );
}


function Evidence({ record }) {
  if (!record) return null;

  return (
    <section className="evidence-grid">

      <div className="evidence-card">
        <span>Issuer</span>
        <strong>{record.issuer}</strong>
      </div>

      <div className="evidence-card">
        <span>SHA-256 document hash</span>
        <code>{record.document_hash}</code>
      </div>

      <div className="evidence-card">
        <span>Digital signature</span>
        <strong>{record.signing_algorithm}</strong>
      </div>

      <div className="evidence-card">
        <span>Key encapsulation</span>
        <strong>{record.kem_algorithm}</strong>
      </div>

      <div className="evidence-card evidence-wide">
        <span>Ledger transaction</span>
        <code>
          {record.transaction_id || 'pending'}
        </code>
      </div>

    </section>
  );
}


function DocumentHistory() {
  const [documents, setDocuments] =
    useState([]);

  const [loading, setLoading] =
    useState(true);

  const [error, setError] =
    useState('');

  const [notice, setNotice] =
    useState('');

  const [page, setPage] =
    useState(0);

  const [total, setTotal] =
    useState(0);

  const [statusCounts, setStatusCounts] =
    useState({});

  const [reconcilingId, setReconcilingId] =
    useState(null);


  async function loadHistory(requestedPage = page) {
    setLoading(true);
    setError('');
    setNotice('');

    try {
      const result = await api(
        `/admin/documents?limit=${REGISTRY_PAGE_SIZE}&offset=${requestedPage * REGISTRY_PAGE_SIZE}`,
        { admin: true }
      );

      const lastPage = Math.max(
        0,
        Math.ceil(result.total / REGISTRY_PAGE_SIZE) - 1
      );
      const effectivePage = Math.min(requestedPage, lastPage);

      if (effectivePage !== requestedPage) {
        await loadHistory(effectivePage);
        return;
      }

      setDocuments(result.items);
      setTotal(result.total);
      setStatusCounts(result.status_counts || {});
      setPage(effectivePage);

    } catch (err) {
      setError(err.message);

    } finally {
      setLoading(false);
    }
  }


  useEffect(() => {
    loadHistory(0);
  }, []);

  async function reconcileDocument(documentId) {
    setReconcilingId(documentId);
    setError('');
    setNotice('');

    try {
      const result = await api(
        `/admin/documents/${documentId}/reconcile`,
        {
          method: 'POST',
          admin: true
        }
      );
      await loadHistory(page);
      setNotice(
        `Reconciliation ${result.action.replaceAll('_', ' ')}. Record status: ${result.status}.`
      );
    } catch (err) {
      setError(err.message);
    } finally {
      setReconcilingId(null);
    }
  }


  async function revokeDocument(documentId) {
    const document =
      documents.find(
        item => item.document_id === documentId
      );

    if (
      !document ||
      document.status === 'REVOKED'
    ) {
      return;
    }

    const reason = window.prompt(
      'Reason for revocation (required):',
      'Document withdrawn by issuing authority'
    );

    if (reason === null) return;

    if (reason.trim().length < 3) {
      setError(
        'Revocation reason must be at least 3 characters.'
      );

      return;
    }

    const confirmed = window.confirm(
      `Revoke document ${documentId}? This will mark it REVOKED in the configured ledger backend.`
    );

    if (!confirmed) return;

    try {
      setError('');
      setNotice('');
      const body = new FormData();

      body.append(
        'reason',
        reason.trim()
      );

      await api(
        `/documents/${documentId}/revoke`,
        {
          method: 'POST',
          body,
          admin: true
        }
      );

      await loadHistory(page);

    } catch (err) {
      setError(err.message);
    }
  }


  async function deleteDocument(documentId) {
    const document =
      documents.find(
        item => item.document_id === documentId
      );

    if (
      !document ||
      document.status !== 'REVOKED'
    ) {
      return;
    }

    const confirmed = window.confirm(
      `Delete application record ${documentId}?\n\n` +
      `Re-registering the same PDF is already allowed after a successful revocation; deletion is optional cleanup. ` +
      `This removes the application record and its application-side audit events.\n\n` +
      `The separate ledger record will not be deleted.`
    );

    if (!confirmed) return;

    try {
      await api(
        `/documents/${documentId}`,
        {
          method: 'DELETE',
          admin: true
        }
      );

      await loadHistory(page);

    } catch (err) {
      setError(err.message);
    }
  }


  if (loading) {
    return (
      <section className="section-card loading-card">

        <div className="section-heading">
          <div>
            <p className="eyebrow">
              Registry
            </p>

            <h2>
              Loading registered documents
            </h2>
          </div>
        </div>

      </section>
    );
  }


  return (
    <section
      className="section-card history"
      id="registry"
    >

      <div className="section-heading">

        <div>

          <p className="eyebrow">
            Registry
          </p>

          <h2>
            Document registry
          </h2>

          <p className="muted">
            Registered records and ledger operations that need attention.
          </p>

          <p className="history-note">
            After successful revocation, the same PDF
            can be registered again as a new record.
            Deleting a revoked record removes only its
            application data; its configured ledger
            record remains.
          </p>

        </div>

        <button
          className="secondary-button"
          type="button"
          onClick={() => loadHistory(page)}
        >
          <Icon name="refresh" />
          Refresh
        </button>

      </div>


      {error && (
        <p className="alert error">
          {error}
        </p>
      )}


      {notice && (
        <p className="alert success" role="status">
          {notice}
        </p>
      )}

      <div className="registry-status-grid" aria-label="Registry status counts">
        <div className="registry-status-card">
          <span className="registry-status-icon registered-icon"><Icon name="check" /></span>
          <span><small>REGISTERED</small><strong>{statusCounts.REGISTERED || 0}</strong></span>
        </div>
        <div className="registry-status-card">
          <span className="registry-status-icon pending-icon"><Icon name="clock" /></span>
          <span><small>NEEDS ATTENTION</small><strong>{(statusCounts.PENDING || 0) + (statusCounts.LEDGER_FAILED || 0)}</strong></span>
        </div>
        <div className="registry-status-card">
          <span className="registry-status-icon conflict-icon"><Icon name="shield" /></span>
          <span><small>CONFLICTS</small><strong>{statusCounts.LEDGER_CONFLICT || 0}</strong></span>
        </div>
        <div className="registry-status-card">
          <span className="registry-status-icon revoked-icon"><Icon name="file" /></span>
          <span><small>REVOKED</small><strong>{statusCounts.REVOKED || 0}</strong></span>
        </div>
      </div>

      {!total && !documents.length && !error && (
        <div className="empty-state">

          <Icon name="file" />

          <strong>
            No document records yet
          </strong>

          <span>
            Register your first document above
            to create a verifiable record.
          </span>

        </div>
      )}


      <div className="history-list">

        {documents.map(document => (

          <article
            className="history-item"
            key={document.document_id}
          >

            <div className="history-main">

              <div className="record-topline">

                <span
                  className={`status-dot ${
                    document.status === 'REVOKED'
                      ? 'revoked'
                      : ['PENDING', 'LEDGER_FAILED'].includes(document.status)
                        ? 'needs-attention'
                        : document.status === 'LEDGER_CONFLICT'
                          ? 'conflict'
                          : ''
                  }`}
                >
                  <i />
                  {document.status || 'REGISTERED'}
                </span>

                <span className="record-date">

                  <Icon name="clock" />

                  {(document.registered_at || document.created_at)
                    ? new Date(
                        document.registered_at || document.created_at
                      ).toLocaleString()
                    : 'Submitted date unavailable'}

                </span>

              </div>


              <h3>
                {document.issuer ||
                  'Unknown issuer'}
              </h3>


              <code className="document-id">
                {document.document_id}
              </code>


              <div className="history-details">

                <div>
                  <span>Signature</span>
                  <strong>
                    {document.signing_algorithm}
                  </strong>
                </div>

                <div>
                  <span>KEM</span>
                  <strong>
                    {document.kem_algorithm}
                  </strong>
                </div>

                <div>
                  <span>File size</span>
                  <strong>
                    {document.size_bytes
                      ?.toLocaleString() || '—'} bytes
                  </strong>
                </div>

              </div>

              {['PENDING', 'LEDGER_FAILED', 'LEDGER_CONFLICT'].includes(document.status) && (
                <div className={`reconciliation-note ${document.status === 'LEDGER_CONFLICT' ? 'conflict' : ''}`}>
                  <strong>
                    {document.status === 'LEDGER_CONFLICT'
                      ? 'Manual investigation required'
                      : document.status === 'PENDING'
                        ? 'Ledger result is pending'
                        : 'Ledger registration needs attention'}
                  </strong>
                  <p>
                    {document.reconciliation_detail ||
                      (document.status === 'PENDING'
                        ? 'The process ended before its ledger result was saved. Check the ledger before accepting this record.'
                        : document.status === 'LEDGER_CONFLICT'
                          ? 'The application and ledger evidence differ. Automatic retries are disabled to avoid overwriting evidence.'
                          : 'No operation detail is available. You can safely check the ledger and retry reconciliation.')}
                  </p>
                  {document.reconciliation_result && (
                    <small>Last operation: {document.reconciliation_result}</small>
                  )}
                </div>
              )}


              <details>

                <summary>
                  View cryptographic evidence
                </summary>

                <div className="history-evidence">

                  <p>
                    <strong>
                      SHA-256
                    </strong>

                    <code>
                      {document.document_hash}
                    </code>
                  </p>

                  <p>
                    <strong>
                      Signature digest
                    </strong>

                    <code>
                      {document.signature_digest}
                    </code>
                  </p>

                  <p>
                    <strong>
                      Key fingerprint
                    </strong>

                    <code>
                      {document.key_fingerprint}
                    </code>
                  </p>

                  <p>
                    <strong>
                      Ledger transaction
                    </strong>

                    <code>
                      {document.transaction_id ||
                        'pending'}
                    </code>
                  </p>


                  {document.status ===
                    'REVOKED' && (
                    <>
                      <p>
                        <strong>
                          Revocation reason
                        </strong>

                        <span>
                          {document.revocation_reason ||
                            '—'}
                        </span>
                      </p>

                      <p>
                        <strong>
                          Revocation transaction
                        </strong>

                        <code>
                          {document.revocation_transaction_id ||
                            'pending'}
                        </code>
                      </p>
                    </>
                  )}

                </div>

              </details>

            </div>


            <div className="history-actions">

              {['PENDING', 'LEDGER_FAILED'].includes(document.status) ? (
                <button
                  type="button"
                  className="primary-button compact reconcile-button"
                  disabled={reconcilingId === document.document_id}
                  onClick={() => reconcileDocument(document.document_id)}
                >
                  {reconcilingId === document.document_id
                    ? 'Checking ledger…'
                    : 'Reconcile ledger'}
                  {reconcilingId !== document.document_id && <Icon name="refresh" />}
                </button>
              ) : document.status === 'LEDGER_CONFLICT' ? (
                <div className="conflict-action-note">
                  <Icon name="shield" />
                  <span>Do not retry automatically</span>
                </div>
              ) : (
                <>
                  <div className="qr-frame small-qr">
                    <img
                      src={`/api/v1/documents/${document.document_id}/qr`}
                      alt="Verification QR code"
                    />
                  </div>
                  <a
                    className="primary-button compact"
                    href={`/verify/${document.document_id}`}
                  >
                    Verify record
                    <Icon name="arrow" />
                  </a>
                  {document.status === 'REVOKED' ? (
                    <button
                      type="button"
                      className="danger-button compact"
                      onClick={() => deleteDocument(document.document_id)}
                    >
                      Delete record
                    </button>
                  ) : (
                <button
                  type="button"
                  className="danger-button compact"
                  onClick={() =>
                    revokeDocument(
                      document.document_id
                    )
                  }
                >
                  Revoke record
                </button>
                  )}
                </>
              )}

            </div>

          </article>

        ))}

      </div>

      {total > REGISTRY_PAGE_SIZE && (
        <nav className="history-pagination" aria-label="Registry pages">
          <button
            className="secondary-button"
            type="button"
            disabled={page === 0}
            onClick={() => loadHistory(page - 1)}
          >
            Previous
          </button>
          <span>
            Showing {page * REGISTRY_PAGE_SIZE + 1}–
            {Math.min((page + 1) * REGISTRY_PAGE_SIZE, total)} of {total}
          </span>
          <button
            className="secondary-button"
            type="button"
            disabled={(page + 1) * REGISTRY_PAGE_SIZE >= total}
            onClick={() => loadHistory(page + 1)}
          >
            Next
          </button>
        </nav>
      )}

    </section>
  );
}


function Register() {

  const [file, setFile] =
    useState(null);

  const [issuer, setIssuer] =
    useState(
      'university-issuing-authority-v1'
    );

  const [signingMode, setSigningMode] =
    useState('demo');

  const [externalSignature, setExternalSignature] =
    useState('');

  const [externalPublicKey, setExternalPublicKey] =
    useState('');

  const [busy, setBusy] =
    useState(false);

  const [error, setError] =
    useState('');


  async function submit(event) {
    event.preventDefault();

    if (!file) {
      return setError(
        'Choose a document to register.'
      );
    }

    if (
      signingMode === 'external' &&
      (!externalSignature.trim() || !externalPublicKey.trim())
    ) {
      return setError(
        'Provide the issuer-generated signature and public key.'
      );
    }

    setBusy(true);
    setError('');

    const body =
      new FormData();

    body.append(
      'file',
      file
    );

    body.append(
      'issuer',
      issuer
    );

    if (signingMode === 'external') {
      body.append('signature_b64', externalSignature.trim());
      body.append('signing_public_key_b64', externalPublicKey.trim());
    }

    try {

      const registered =
        await api(
          '/documents/register',
          {
            method: 'POST',
            body,
            admin: true
          }
        );

      window.location.href =
        `/document/${registered.document_id}`;

    } catch (err) {

      setError(err.message);

    } finally {

      setBusy(false);
    }
  }


  return (
    <section
      className="section-card register-card register-only"
      id="register"
    >

      <div className="card-label">
        <span>01</span>
        Register evidence
      </div>

      <h2>
        Create a verifiable record.
      </h2>

      <p className="muted">
        Upload the original document.
        Choose the demo signing key or provide
        evidence signed locally by the issuer.
        The source file is never modified.
      </p>


      <form onSubmit={submit}>

        <label>

          <span>
            Issuer ID (as enrolled)
          </span>

          <input
            value={issuer}
            onChange={e =>
              setIssuer(e.target.value)
            }
            minLength="2"
            maxLength="64"
            required
            placeholder="University or issuing authority"
          />

        </label>

        <label>
          <span>Signing method</span>
          <select
            value={signingMode}
            onChange={event => setSigningMode(event.target.value)}
          >
            <option value="demo">Server-managed demo key</option>
            <option value="external">Issuer-signed external key</option>
          </select>
        </label>

        {signingMode === 'external' && (
          <div className="external-signature-fields">
            <p>
              From the project root on the issuer's computer, generate a key once and sign
              each PDF locally. Share only the public key and signature with the admin.
              Never upload the private key.
            </p>
            <pre><code>{`docker compose --profile issuer-tools run --build --rm issuer-tools keygen --output /issuer-workspace/my-issuer.json
docker compose --profile issuer-tools run --rm issuer-tools sign --key /issuer-workspace/my-issuer.json --file /issuer-workspace/certificate.pdf --issuer "ISSUER_ID" --output /issuer-workspace/certificate-signature.json`}</code></pre>
            <p>Enroll the printed public key first. Then copy <code>signing_public_key_b64</code> and <code>signature_b64</code> from the signing JSON below.</p>
            <label>
              <span>Issuer public key (Base64)</span>
              <textarea
                rows={3}
                required
                value={externalPublicKey}
                onChange={event => setExternalPublicKey(event.target.value)}
                placeholder="Paste signing_public_key_b64 from the local signing output"
              />
            </label>
            <label>
              <span>Issuer signature (Base64)</span>
              <textarea
                rows={3}
                required
                value={externalSignature}
                onChange={event => setExternalSignature(event.target.value)}
                placeholder="Paste signature_b64 from the local signing output"
              />
            </label>
          </div>
        )}

        <label
          className={`dropzone ${
            file ? 'has-file' : ''
          }`}
        >

          <input
            type="file"
            accept="application/pdf,.pdf"
            onChange={e =>
              setFile(
                e.target.files?.[0] ||
                null
              )
            }
            required
          />

          <span className="upload-icon">
            <Icon name="upload" />
          </span>

          <strong>
            {file
              ? file.name
              : 'Choose a document'}
          </strong>

          <small>
            {file
              ? `${file.size.toLocaleString()} bytes selected`
              : 'PDF document only'}
          </small>

          <span className="browse-text">
            Browse files
          </span>

        </label>


        <button
          className="primary-button submit-button"
          disabled={busy}
        >
          {busy
            ? 'Creating cryptographic evidence…'
            : 'Register document'}

          {!busy && (
            <Icon name="arrow" />
          )}

        </button>

      </form>


      {error && (
        <p className="alert error">
          {error}
        </p>
      )}


      <div className="security-note">

        <Icon name="lock" />

        <span>
          Files are processed through the
          protected verification pipeline.
        </span>

      </div>

    </section>
  );
}


function DocumentResult({
  documentId
}) {

  const [record, setRecord] =
    useState(null);

  const [error, setError] =
    useState('');


  useEffect(() => {

    api(`/documents/${documentId}`)
      .then(setRecord)
      .catch(e =>
        setError(e.message)
      );

  }, [documentId]);


  return (
    <div className="app-shell">

      <header className="site-header">

        <a
          className="brand"
          href="/"
        >
          <span className="brand-mark">
            Q
          </span>

          QuantumProof
        </a>

        <span className="header-badge">
          <i />
          Registration complete
        </span>

      </header>


      <main className="result-page">

        <a
          className="back-link"
          href="/"
        >
          ← Register another document
        </a>


        {error ? (

          <p className="alert error">
            {error}
          </p>

        ) : !record ? (

          <div className="section-card result-loading">

            <p className="eyebrow">
              Registration
            </p>

            <h1>
              Loading your verification record…
            </h1>

          </div>

        ) : (

          <>

            <div className="result-page-intro">

              <div className="success-mark">
                <Icon name="check" />
              </div>

              <div>

                <p className="eyebrow">
                  Registration complete
                </p>

                <h1>
                  Evidence committed.
                </h1>

                <p className="muted">
                  Your document now has a persistent
                  cryptographic record. Share the QR
                  code or verification link with a verifier.
                </p>

              </div>

            </div>


            <section className="result-grid">

              <div className="section-card result-summary">

                <p className="eyebrow">
                  Verification record
                </p>

                <h2>
                  Document identity
                </h2>


                <div className="id-block">

                  <span>
                    Document ID
                  </span>

                  <code>
                    {record.document_id}
                  </code>

                </div>


                <div className="result-meta">

                  <div>
                    <span>Issuer</span>
                    <strong>
                      {record.issuer}
                    </strong>
                  </div>

                  <div>
                    <span>Signature</span>
                    <strong>
                      {record.signing_algorithm}
                    </strong>
                  </div>

                  <div>
                    <span>KEM</span>
                    <strong>
                      {record.kem_algorithm}
                    </strong>
                  </div>

                  <div>
                    <span>File size</span>
                    <strong>
                      {record.size_bytes?.toLocaleString()}
                      {' '}bytes
                    </strong>
                  </div>

                </div>


                <a
                  className="primary-button full"
                  href={`/verify/${record.document_id}`}
                >
                  Open verification page
                  <Icon name="arrow" />
                </a>


                <a
                  className="secondary-button full secondary-link"
                  href="/"
                >
                  Register another document
                </a>

              </div>


              <div className="section-card result-qr-card">

                <p className="eyebrow">
                  Shareable verification
                </p>

                <h2>
                  Scan to verify.
                </h2>

                <div className="qr-frame result-qr">

                  <img
                    alt="Verification QR code"
                    src={`/api/v1/documents/${record.document_id}/qr`}
                  />

                </div>

                <p className="muted qr-caption">
                  Anyone with this QR code can open
                  the public verification page for this record.
                </p>

              </div>

            </section>


            <section className="section-card result-evidence">

              <div className="section-heading">

                <div>

                  <p className="eyebrow">
                    Cryptographic evidence
                  </p>

                  <h2>
                    Record integrity
                  </h2>

                </div>

              </div>

              <Evidence record={record} />

            </section>

          </>

        )}

      </main>


      <footer className="site-footer">

        <span>
          QuantumProof
        </span>

        <span>
          Research prototype · SHA-256 · ML-DSA · ML-KEM · Hyperledger Fabric
        </span>

      </footer>

    </div>
  );
}


function Verify({
  documentId
}) {

  const [record, setRecord] =
    useState(null);

  const [audit, setAudit] =
    useState([]);

  const [file, setFile] =
    useState(null);

  const [outcome, setOutcome] =
    useState(null);

  const [error, setError] =
    useState('');

  const [busy, setBusy] =
    useState(false);

  const [loading, setLoading] =
    useState(true);


  useEffect(() => {

    async function load() {

      setLoading(true);
      setError('');

      try {

        const document = await api(
          `/documents/${documentId}`
        );

        setRecord(document);
        setAudit([]);

      } catch (e) {

        setError(e.message);

      } finally {

        setLoading(false);

      }
    }

    load();

  }, [documentId]);


  async function verify(event) {

    event.preventDefault();

    if (!file) {

      return setError(
        'Choose the document you want to verify.'
      );

    }

    setBusy(true);
    setError('');

    const body =
      new FormData();

    body.append(
      'file',
      file
    );

    try {

      const verification =
        await api(
          `/documents/${documentId}/verify`,
          {
            method: 'POST',
            body
          }
        );

      setOutcome(
        verification
      );

      setAudit([]);

    } catch (err) {

      setError(
        err.message
      );

    } finally {

      setBusy(false);

    }
  }


  const isValid =
    outcome?.overall_status === 'VALID';

  const isRevoked =
    outcome?.overall_status === 'REVOKED';

  const recordIsRevoked =
    record?.status === 'REVOKED';

  const outcomeClass =
    outcome
      ? outcome.overall_status.toLowerCase()
      : '';


  return (
    <div className="verify-shell">

      <header className="site-header">

        <a
          className="brand"
          href="/"
        >
          <span className="brand-mark">
            Q
          </span>

          QuantumProof
        </a>

        <span className="header-badge">
          <i />
          Public verification
        </span>

      </header>


      <main className="verify-page">

        <a
          className="back-link"
          href="/"
        >
          ← Back to QuantumProof
        </a>


        <div className="verify-intro">

          <p className="eyebrow">
            Authenticity check
          </p>

          <h1>
            Verify a document
            <br />
            <span>
              against its original evidence.
            </span>
          </h1>

          <p className="muted">
            Upload the document you received.
            QuantumProof compares its cryptographic
            fingerprint with the registered evidence
            and checks the ledger record.
          </p>

        </div>


        {error && (
          <p className="alert error">
            {error}
          </p>
        )}


        <div className="verification-id">

          <span>
            Verification record
          </span>

          <code>
            {documentId}
          </code>

        </div>


        {loading && (

          <section className="section-card loading-card">

            <p className="muted">
              Loading verification record…
            </p>

          </section>

        )}


        {!loading && record && (

          <>

            <Evidence record={record} />


            {recordIsRevoked ? (

              <section className="outcome revoked section-card">

                <div className="outcome-header">

                  <div className="outcome-icon invalid">

                    <Icon name="shield" />

                  </div>

                  <div>

                    <p className="eyebrow">
                      REVOKED
                    </p>

                    <h2>
                      This document record
                      has been revoked.
                    </h2>

                    <p className="muted">
                      This record cannot be treated
                      as a valid active credential.
                    </p>

                  </div>

                </div>


                <p className="alert error">

                  <strong>
                    Revocation reason:
                  </strong>

                  {' '}

                  {record.revocation_reason ||
                    'No reason supplied.'}

                </p>


                <div className="check-grid">

                  <div className="fail">

                    <span>
                      Record status
                    </span>

                    <strong>
                      REVOKED
                    </strong>

                    <small>
                      Credential is no longer active
                    </small>

                  </div>


                  <div className="pass">

                    <span>
                      Ledger backend
                    </span>

                    <strong>
                      {record.ledger_backend}
                    </strong>

                    <small>
                      Configured registration backend
                    </small>

                  </div>


                  <div className="pass">

                    <span>
                      Record status
                    </span>

                    <strong>
                      REVOKED
                    </strong>

                    <small>
                      This credential is no longer active
                    </small>

                  </div>

                </div>


                {record.revoked_at && (

                  <div className="verification-id">

                    <span>
                      Revoked at
                    </span>

                    <code>
                      {new Date(
                        record.revoked_at
                      ).toLocaleString()}
                    </code>

                  </div>

                )}


                {record.revocation_transaction_id && (

                  <div className="verification-id">

                    <span>
                      Revocation transaction
                    </span>

                    <code>
                      {record.revocation_transaction_id}
                    </code>

                  </div>

                )}


                <p className="alert error">

                  Verification upload is disabled
                  because this record has already
                  been revoked.

                </p>

              </section>

            ) : (

              <form
                className="section-card verify-form"
                onSubmit={verify}
              >

                <div>

                  <p className="eyebrow">
                    02 · Compare
                  </p>

                  <h2>
                    Upload the document to verify.
                  </h2>

                  <p className="muted">
                    The uploaded file is checked
                    against the registered
                    cryptographic evidence.
                  </p>

                </div>


                <label
                  className={`dropzone verify-dropzone ${
                    file ? 'has-file' : ''
                  }`}
                >

                  <input
                    type="file"
                    accept="application/pdf,.pdf"
                    onChange={e =>
                      setFile(
                        e.target.files?.[0] ||
                        null
                      )
                    }
                    required
                  />

                  <span className="upload-icon">
                    <Icon name="search" />
                  </span>

                  <strong>
                    {file
                      ? file.name
                      : 'Select the candidate document'}
                  </strong>

                  <small>
                    {file
                      ? `${file.size.toLocaleString()} bytes selected`
                      : 'Upload the file you want to authenticate'}
                  </small>

                  <span className="browse-text">
                    Browse files
                  </span>

                </label>


                <button
                  className="primary-button"
                  disabled={busy}
                >

                  {busy
                    ? 'Checking cryptographic evidence…'
                    : 'Verify document'}

                  {!busy && (
                    <Icon name="arrow" />
                  )}

                </button>

              </form>

            )}

          </>

        )}


        {outcome && (

          <section
            className={`outcome ${outcomeClass} section-card`}
          >

            <div className="outcome-header">

              <div
                className={`outcome-icon ${
                  isValid
                    ? 'valid'
                    : 'invalid'
                }`}
              >

                <Icon
                  name={
                    isValid
                      ? 'check'
                      : 'shield'
                  }
                />

              </div>


              <div>

                <p className="eyebrow">
                  {outcome.overall_status}
                </p>

                <h2>
                  {outcome.detail}
                </h2>

              </div>

            </div>


            {isRevoked && (

              <p className="alert error">

                This record has been revoked
                and must not be accepted as an
                authentic active credential.

              </p>

            )}


            <div className="check-grid">

              <div
                className={
                  outcome.document_hash_matches
                    ? 'pass'
                    : 'fail'
                }
              >

                <span>
                  Document hash
                </span>

                <strong>
                  {outcome.document_hash_matches
                    ? 'MATCH'
                    : 'MISMATCH'}
                </strong>

                <small>
                  {outcome.document_hash_matches
                    ? 'File fingerprint matches'
                    : 'File fingerprint differs'}
                </small>

              </div>


              <div
                className={
                  outcome.signature_valid
                    ? 'pass'
                    : 'fail'
                }
              >

                <span>
                  Digital signature
                </span>

                <strong>
                  {outcome.signature_valid
                    ? 'VALID'
                    : 'INVALID'}
                </strong>

                <small>
                  ML-DSA evidence check
                </small>

              </div>


              <div
                className={
                  outcome.ledger_valid
                    ? 'pass'
                    : 'fail'
                }
              >

                <span>
                  Ledger record
                </span>

                <strong>
                  {outcome.ledger_valid
                    ? 'CONFIRMED'
                    : 'NOT CONFIRMED'}
                </strong>

                <small>
                  {outcome.ledger_backend} evidence check
                </small>

              </div>

            </div>

          </section>

        )}


        {audit.length > 0 && (

          <section className="section-card audit-card">

            <div className="section-heading">

              <div>

                <p className="eyebrow">
                  Audit trail
                </p>

                <h2>
                  Verification history
                </h2>

              </div>

            </div>


            <div className="audit-list">

              {audit.map(
                (event, index) => (

                  <article
                    className="audit-row"
                    key={index}
                  >

                    <div className="audit-marker">
                      <i />
                    </div>

                    <div>

                      <strong>
                        {event.action}
                      </strong>

                      <p>
                        {event.detail}
                      </p>

                    </div>

                    <div
                      className={`audit-result ${String(
                        event.result
                      ).toLowerCase()}`}
                    >
                      {event.result}
                    </div>

                    <time>

                      {event.occurred_at
                        ? new Date(
                            event.occurred_at
                          ).toLocaleString()
                        : ''}

                    </time>

                  </article>

                )
              )}

            </div>

          </section>

        )}

      </main>


      <footer className="site-footer">
        QuantumProof · Cryptographic document verification prototype
      </footer>

    </div>
  );
}


function Benchmark() {

  const [data, setData] =
    useState(null);

  const [busy, setBusy] =
    useState(false);

  const [error, setError] =
    useState('');

  const [showResults, setShowResults] =
    useState(false);


  async function run() {

    setBusy(true);
    setError('');

    try {

      const result =
        await api(
          '/benchmarks/run',
          {
            method: 'POST',
            headers: {
              'Content-Type':
                'application/json'
            },
            body: JSON.stringify({
              iterations: 100
            })
          }
        );

      setData(result);
      setShowResults(true);

      requestAnimationFrame(() => {

        document
          .getElementById(
            'benchmark-results'
          )
          ?.scrollIntoView({
            behavior: 'smooth',
            block: 'nearest'
          });

      });

    } catch (e) {

      setError(e.message);

    } finally {

      setBusy(false);

    }
  }


  function hideResults() {
    setShowResults(false);
  }


  return (
    <div className="benchmark-workspace" id="benchmark">
      <section className="section-card benchmark benchmark-run-card">

      <div className="section-heading">

        <div>

          <p className="eyebrow">
            BENCHMARK RUNNER
          </p>

          <h2>
            Measure what matters.
          </h2>

          <p className="muted">
            Compare post-quantum operations with classical baselines.
            Each run performs 100 measured iterations after warm-up.
          </p>

        </div>


        <div className="benchmark-actions">

          <button
            className="secondary-button"
            onClick={run}
            disabled={busy}
          >
            {busy
              ? 'Benchmarking…'
              : 'Run benchmark'}
          </button>


          {showResults && data && (

            <button
              className="secondary-button hide-results-button"
              onClick={hideResults}
            >
              Hide results
            </button>

          )}

        </div>

      </div>


      {error && (
        <p className="alert error">
          {error}
        </p>
      )}


      {showResults && data && (

        <div
          className="benchmark-results"
          id="benchmark-results"
        >

          <div className="results-toolbar">

            <div>

              <span className="results-label">
                Latest benchmark
              </span>

              <strong>
                100 controlled iterations
              </strong>

            </div>

            <button
              type="button"
              className="results-close"
              onClick={hideResults}
              aria-label="Hide benchmark results"
            >
              ×
            </button>

          </div>


          <div className="table-wrap">

            <table>

              <thead>

                <tr>
                  <th>Family</th>
                  <th>Algorithm</th>
                  <th>Operation</th>
                  <th>Mean</th>
                  <th>P95</th>
                </tr>

              </thead>


              <tbody>

                {data.results.map(
                  (row, index) => (

                    <tr key={index}>

                      <td>
                        {row.family}
                      </td>

                      <td>
                        {row.algorithm}
                      </td>

                      <td>
                        {row.operation}
                      </td>

                      <td>
                        {row.mean_ms} ms
                      </td>

                      <td>
                        {row.p95_ms} ms
                      </td>

                    </tr>

                  )
                )}

              </tbody>

            </table>

          </div>

        </div>

      )}

      </section>

      <aside className="benchmark-method">
        <div className="benchmark-method-heading">
          <span className="method-icon"><Icon name="ledger" /></span>
          <div>
            <p className="eyebrow">WHAT GETS MEASURED</p>
            <h2>Six operations. One runtime.</h2>
          </div>
        </div>
        <div className="method-row">
          <span className="method-number">01</span>
          <div><strong>Digital signatures</strong><small>ML-DSA-65 compared with Ed25519</small></div>
          <span className="method-arrow">↗</span>
        </div>
        <div className="method-row">
          <span className="method-number">02</span>
          <div><strong>Key establishment</strong><small>ML-KEM-768 compared with X25519</small></div>
          <span className="method-arrow">↗</span>
        </div>
        <div className="method-row">
          <span className="method-number">03</span>
          <div><strong>Statistical summary</strong><small>Mean, median, standard deviation and P95</small></div>
          <span className="method-arrow">↗</span>
        </div>
        <p className="benchmark-caveat">
          Results describe this container and runtime only. They are experimental measurements, not a production capacity estimate.
        </p>
      </aside>
    </div>
  );
}


function AdminLoginPage() {
  const [adminId, setAdminId] = useState('');
  const [password, setPassword] = useState('');
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState('');

  async function submit(event) {
    event.preventDefault();
    setBusy(true);
    setError('');

    const body = new FormData();
    body.append('admin_id', adminId.trim());
    body.append('password', password);

    try {
      await api('/auth/login', {
        method: 'POST',
        body
      });
      window.location.href = '/register';
    } catch (err) {
      setError(err.message);
    } finally {
      setBusy(false);
    }
  }

  return (
    <div className="app-shell">
      <header className="site-header">
        <a className="brand" href="/">
          <span className="brand-mark">Q</span>
          QuantumProof
        </a>
        <span className="header-badge"><i /> Admin authentication</span>
      </header>

      <main className="subpage auth-page">
        <a className="back-link" href="/">← Back to public verification</a>
        <section className="auth-layout">
          <div className="auth-copy">
            <span className="auth-kicker"><i /> ISSUER WORKSPACE</span>
            <h1>Issue with confidence.<br /><span>Verify with proof.</span></h1>
            <p>
              A secure workspace for registering documents and managing
              their cryptographic evidence.
            </p>
            <div className="auth-benefits">
              <div><span className="benefit-index">01</span><span><strong>Register</strong><small>Create a signed document record</small></span></div>
              <div><span className="benefit-index">02</span><span><strong>Manage</strong><small>Review the shared document registry</small></span></div>
              <div><span className="benefit-index">03</span><span><strong>Verify</strong><small>Share independent verification links</small></span></div>
            </div>
            <div className="auth-security-note">
              <Icon name="lock" />
              <span>Administrator access is protected by an expiring secure session.</span>
            </div>
          </div>

          <section className="section-card auth-card">
            <div className="auth-card-heading">
              <span className="auth-card-icon"><Icon name="shield" /></span>
              <div>
                <p className="eyebrow">WELCOME BACK</p>
                <h2>Sign in to continue</h2>
                <p className="muted">Use your administrator credentials to access the issuer portal.</p>
              </div>
            </div>
            <form onSubmit={submit} className="auth-form">
              <label>
                <span>Admin ID</span>
                <input
                  value={adminId}
                  onChange={e => setAdminId(e.target.value)}
                  autoComplete="username"
                  placeholder="Enter your admin ID"
                  required
                />
              </label>
              <label>
                <span>Password</span>
                <input
                  type="password"
                  value={password}
                  onChange={e => setPassword(e.target.value)}
                  autoComplete="current-password"
                  placeholder="Enter your password"
                  required
                />
              </label>
              {error && <div className="form-error">{error}</div>}
              <button className="primary-button" disabled={busy} type="submit">
                {busy ? 'Signing in…' : 'Continue to workspace'}
                <Icon name="arrow" />
              </button>
            </form>
            <p className="auth-card-footnote"><i /> Your session uses an HTTP-only cookie and expires automatically.</p>
          </section>
        </section>
      </main>
    </div>
  );
}


async function adminLogout() {
  try {
    await api('/auth/logout', { method: 'POST' });
  } finally {
    window.location.replace('/admin/login');
  }
}

function AdminHeader({ badge = 'Administrator' }) {
  return (
    <header className="site-header">
      <a className="brand" href="/">
        <span className="brand-mark">Q</span>
        QuantumProof
      </a>
      <nav className="nav-links">
        <a href="/register">Register</a>
        <a href="/registry">Registry</a>
        <a href="/admin/issuers">Issuers</a>
        <a href="/benchmark">Benchmark</a>
      </nav>
      <span className="header-badge"><i /> {badge}</span>
      <button className="secondary-button" onClick={adminLogout}>Logout</button>
    </header>
  );
}

function AdminRoute({ children }) {
  const [state, setState] = useState('loading');

  useEffect(() => {
    api('/auth/me', { admin: true })
      .then(() => setState('ok'))
      .catch(() => setState('login'));
  }, []);

  useEffect(() => {
    const expire = () => setState('login');
    window.addEventListener('quantumproof:session-expired', expire);
    return () => window.removeEventListener('quantumproof:session-expired', expire);
  }, []);

  if (state === 'loading') {
    return <section className="section-card loading-card"><h2>Checking admin session…</h2></section>;
  }

  if (state === 'login') {
    window.location.replace('/admin/login');
    return null;
  }

  return children;
}


function AdminHomeRedirect() {
  useEffect(() => {
    window.location.replace('/register');
  }, []);

  return <section className="section-card loading-card"><h2>Opening document registration…</h2></section>;
}


function IssuerManagement() {
  const [issuers, setIssuers] = useState([]);
  const [loading, setLoading] = useState(true);
  const [busy, setBusy] = useState('');
  const [error, setError] = useState('');
  const [notice, setNotice] = useState('');
  const [rotationIssuer, setRotationIssuer] = useState('');
  const [enrollment, setEnrollment] = useState({
    issuer_id: '',
    organization: '',
    public_key_b64: '',
    expires_at: ''
  });
  const [rotation, setRotation] = useState({
    public_key_b64: '',
    expires_at: ''
  });

  async function loadIssuers() {
    setLoading(true);
    setError('');
    try {
      const result = await api('/admin/issuers', { admin: true });
      setIssuers(result.items);
    } catch (err) {
      setError(err.message);
    } finally {
      setLoading(false);
    }
  }

  useEffect(() => {
    loadIssuers();
  }, []);

  function toApiExpiration(value) {
    return value ? new Date(value).toISOString() : null;
  }

  async function enrollIssuer(event) {
    event.preventDefault();
    setBusy('enroll');
    setError('');
    setNotice('');
    try {
      const result = await api('/admin/issuers', {
        method: 'POST',
        admin: true,
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          issuer_id: enrollment.issuer_id.trim(),
          organization: enrollment.organization.trim(),
          public_key_b64: enrollment.public_key_b64.trim(),
          expires_at: toApiExpiration(enrollment.expires_at)
        })
      });
      setEnrollment({
        issuer_id: '',
        organization: '',
        public_key_b64: '',
        expires_at: ''
      });
      setNotice(`Issuer ${result.issuer_id} enrolled. Verify the key fingerprint with the issuer out of band.`);
      await loadIssuers();
    } catch (err) {
      setError(err.message);
    } finally {
      setBusy('');
    }
  }

  async function setIssuerStatus(issuer, nextStatus) {
    setBusy(issuer.issuer_id);
    setError('');
    setNotice('');
    try {
      const result = await api(
        `/admin/issuers/${encodeURIComponent(issuer.issuer_id)}/status`,
        {
          method: 'PATCH',
          admin: true,
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ status: nextStatus })
        }
      );
      setNotice(
        result.action === 'unchanged'
          ? `${issuer.issuer_id} is already ${result.status}.`
          : `${issuer.issuer_id} is now ${result.status}.`
      );
      await loadIssuers();
    } catch (err) {
      setError(err.message);
    } finally {
      setBusy('');
    }
  }

  async function rotateIssuerKey(event, issuer) {
    event.preventDefault();
    setBusy(issuer.issuer_id);
    setError('');
    setNotice('');
    try {
      const result = await api(
        `/admin/issuers/${encodeURIComponent(issuer.issuer_id)}/rotate-key`,
        {
          method: 'POST',
          admin: true,
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({
            public_key_b64: rotation.public_key_b64.trim(),
            expires_at: toApiExpiration(rotation.expires_at)
          })
        }
      );
      setRotation({ public_key_b64: '', expires_at: '' });
      setRotationIssuer('');
      setNotice(`Signing key rotated for ${result.issuer_id}. Existing documents retain their original evidence.`);
      await loadIssuers();
    } catch (err) {
      setError(err.message);
    } finally {
      setBusy('');
    }
  }

  return (
    <div className="app-shell">
      <AdminHeader badge="Issuer management" />
      <main className="subpage issuer-management-page">
        <a className="back-link" href="/register">← Back to issuer workspace</a>
        <div className="subpage-intro">
          <p className="eyebrow">TRUSTED SIGNERS</p>
          <h1>Manage issuers and signing keys.</h1>
          <p className="muted">
            Enroll external public keys, rotate signing keys, and suspend issuers.
            Private keys stay with the issuer.
          </p>
        </div>

        {error && <p className="alert error" role="alert">{error}</p>}
        {notice && <p className="alert success" role="status">{notice}</p>}

        <div className="issuer-management-layout">
          <section className="section-card issuer-enroll-card">
            <div className="issuer-panel-heading">
              <span className="issuer-panel-icon"><Icon name="key" /></span>
              <div>
                <p className="eyebrow">NEW TRUST RELATIONSHIP</p>
                <h2>Enroll an issuer</h2>
              </div>
            </div>
            <form className="issuer-form" onSubmit={enrollIssuer}>
              <label>
                <span>Issuer ID</span>
                <input
                  required
                  maxLength={64}
                  value={enrollment.issuer_id}
                  onChange={event => setEnrollment({
                    ...enrollment,
                    issuer_id: event.target.value
                  })}
                  placeholder="Example University"
                />
              </label>
              <label>
                <span>Organization name</span>
                <input
                  required
                  maxLength={160}
                  value={enrollment.organization}
                  onChange={event => setEnrollment({
                    ...enrollment,
                    organization: event.target.value
                  })}
                  placeholder="Example University"
                />
              </label>
              <label>
                <span>Signing public key (Base64)</span>
                <textarea
                  required
                  rows={4}
                  value={enrollment.public_key_b64}
                  onChange={event => setEnrollment({
                    ...enrollment,
                    public_key_b64: event.target.value
                  })}
                  placeholder="Paste the issuer's ML-DSA public key"
                />
              </label>
              <label>
                <span>Optional expiration</span>
                <input
                  type="datetime-local"
                  value={enrollment.expires_at}
                  onChange={event => setEnrollment({
                    ...enrollment,
                    expires_at: event.target.value
                  })}
                />
              </label>
              <div className="issuer-enroll-warning">
                <Icon name="lock" />
                <p>Never upload a private key. Confirm the public-key fingerprint with the issuer through a trusted channel before enrollment.</p>
              </div>
              <button className="primary-button" type="submit" disabled={busy === 'enroll'}>
                {busy === 'enroll' ? 'Enrolling…' : 'Enroll issuer'}
                <Icon name="arrow" />
              </button>
            </form>
          </section>

          <section className="issuer-records">
            <div className="issuer-records-heading">
              <div>
                <p className="eyebrow">TRUST REGISTER</p>
                <h2>Enrolled issuers</h2>
              </div>
              <span>{issuers.length} total</span>
            </div>
            {loading ? (
              <div className="section-card loading-card"><h2>Loading issuers…</h2></div>
            ) : issuers.length === 0 ? (
              <div className="empty-state">
                <Icon name="shield" />
                <strong>No issuers enrolled</strong>
                <span>Enroll an external issuer public key to start a trust relationship.</span>
              </div>
            ) : (
              <div className="issuer-admin-list">
                {issuers.map(issuer => (
                  <article className="issuer-admin-card" key={issuer.issuer_id}>
                    <div className="issuer-admin-topline">
                      <div>
                        <span className={`issuer-status-badge ${issuer.status.toLowerCase()}`}>
                          <i />
                          {issuer.status}
                        </span>
                        {issuer.server_managed && (
                          <span className="issuer-managed-label">DEMO KEY · SERVER MANAGED</span>
                        )}
                        <h3>{issuer.organization}</h3>
                        <code>{issuer.issuer_id}</code>
                      </div>
                      <div className="issuer-admin-actions">
                        <button
                          className={issuer.status === 'ACTIVE' ? 'danger-button compact' : 'primary-button compact'}
                          type="button"
                          disabled={busy === issuer.issuer_id}
                          onClick={() => setIssuerStatus(
                            issuer,
                            issuer.status === 'ACTIVE' ? 'SUSPENDED' : 'ACTIVE'
                          )}
                        >
                          {issuer.status === 'ACTIVE' ? 'Suspend issuer' : 'Reactivate'}
                        </button>
                        {!issuer.server_managed && (
                          <button
                            className="secondary-button compact"
                            type="button"
                            onClick={() => {
                              setRotationIssuer(
                                rotationIssuer === issuer.issuer_id ? '' : issuer.issuer_id
                              );
                              setRotation({ public_key_b64: '', expires_at: '' });
                            }}
                          >
                            Rotate key
                          </button>
                        )}
                      </div>
                    </div>
                    <div className="issuer-key-evidence">
                      <span>
                        <small>Signing algorithm</small>
                        <strong>{issuer.signing_algorithm}</strong>
                      </span>
                      <span>
                        <small>Current fingerprint</small>
                        <code>{issuer.key_fingerprint}</code>
                      </span>
                      <span>
                        <small>Expires</small>
                        <strong>{issuer.expires_at ? new Date(issuer.expires_at).toLocaleString() : 'No expiry set'}</strong>
                      </span>
                    </div>
                    {rotationIssuer === issuer.issuer_id && (
                      <form className="issuer-rotation-form" onSubmit={event => rotateIssuerKey(event, issuer)}>
                        <strong>Rotate signing key</strong>
                        <p>Provide the new public key. Previously issued documents remain verifiable with their recorded key.</p>
                        <label>
                          <span>New public key (Base64)</span>
                          <textarea
                            required
                            rows={3}
                            value={rotation.public_key_b64}
                            onChange={event => setRotation({
                              ...rotation,
                              public_key_b64: event.target.value
                            })}
                          />
                        </label>
                        <label>
                          <span>New expiration (optional; blank keeps current expiration)</span>
                          <input
                            type="datetime-local"
                            value={rotation.expires_at}
                            onChange={event => setRotation({
                              ...rotation,
                              expires_at: event.target.value
                            })}
                          />
                        </label>
                        <div className="issuer-rotation-actions">
                          <button className="primary-button compact" type="submit" disabled={busy === issuer.issuer_id}>
                            {busy === issuer.issuer_id ? 'Rotating…' : 'Confirm rotation'}
                          </button>
                          <button className="secondary-button compact" type="button" onClick={() => setRotationIssuer('')}>
                            Cancel
                          </button>
                        </div>
                      </form>
                    )}
                    <details className="issuer-history">
                      <summary>Management history ({issuer.history.length})</summary>
                      {issuer.history.length ? (
                        <div className="issuer-history-list">
                          {issuer.history.map((event, index) => (
                            <div className="issuer-history-entry" key={`${event.action}-${index}`}>
                              <div>
                                <strong>{event.action.replaceAll('_', ' ')}</strong>
                                <small>{new Date(event.occurred_at).toLocaleString()} · {event.actor}</small>
                              </div>
                              {(event.previous_key_fingerprint || event.new_key_fingerprint) && (
                                <code>
                                  {event.previous_key_fingerprint || 'Initial key'}
                                  {' → '}
                                  {event.new_key_fingerprint || '—'}
                                </code>
                              )}
                              {event.detail && <p>{event.detail}</p>}
                            </div>
                          ))}
                        </div>
                      ) : (
                        <p className="issuer-history-empty">No management history is available for this pre-existing issuer.</p>
                      )}
                    </details>
                  </article>
                ))}
              </div>
            )}
          </section>
        </div>
      </main>
      <footer className="site-footer">
        <span>QuantumProof</span>
        <span>Issuer trust management</span>
      </footer>
    </div>
  );
}


function RegisterPage() {

  return (
    <div className="app-shell">

      <AdminHeader badge="Issuer portal" />


      <main className="subpage">

        <a
          className="back-link"
          href="/"
        >
          ← Back to verification portal
        </a>


        <div className="workspace-title">
          <div>
            <p className="eyebrow">ISSUER STUDIO / NEW RECORD</p>
            <h1>Create a trusted document record.</h1>
            <p className="muted">Register a PDF once. Share its verification link with anyone who needs to check it.</p>
          </div>
          <span className="workspace-protocol"><i /> SHA-256 <b>·</b> ML-DSA <b>·</b> Ledger</span>
        </div>

        <div className="issuer-layout">
          <aside className="issuer-guide">
            <div className="guide-heading">
              <span className="guide-icon"><Icon name="shield" /></span>
              <div><p className="eyebrow">REGISTRATION FLOW</p><h2>Three steps to proof</h2></div>
            </div>
            <div className="guide-step guide-step-active">
              <span>01</span><div><strong>Choose issuer</strong><small>Use an active registered organization</small></div>
            </div>
            <div className="guide-step">
            <span>02</span><div><strong>Upload original PDF</strong><small>One PDF document at a time</small></div>
            </div>
            <div className="guide-step">
              <span>03</span><div><strong>Share verification link</strong><small>QR code is created after registration</small></div>
            </div>
            <div className="guide-privacy">
              <Icon name="lock" />
              <p><strong>Private by design</strong><br />The PDF is encrypted for storage. Only its compact commitment is sent to the ledger.</p>
            </div>
          </aside>
          <Register />
        </div>

      </main>


      <footer className="site-footer">

        <span>
          QuantumProof
        </span>

        <span>
          Document registration
        </span>

      </footer>

    </div>
  );
}


function RegistryPage() {

  return (
    <div className="app-shell">

      <AdminHeader badge="Document registry" />


      <main className="subpage">

        <a
          className="back-link"
          href="/"
        >
          ← Back to verification portal
        </a>


        <div className="subpage-intro">

          <p className="eyebrow">
            Registry
          </p>

          <h1>
            Registered documents.
          </h1>

          <p className="muted">
            Browse persistent document records
            and open their public verification pages.
          </p>

        </div>


        <DocumentHistory />

      </main>


      <footer className="site-footer">

        <span>
          QuantumProof
        </span>

        <span>
          Document registry
        </span>

      </footer>

    </div>
  );
}


function BenchmarkPage() {

  return (
    <div className="app-shell">

      <AdminHeader badge="Research evaluation" />


      <main className="subpage">

        <a
          className="back-link"
          href="/"
        >
          ← Back to verification portal
        </a>


        <div className="subpage-intro">

          <p className="eyebrow">
            Research evaluation
          </p>

          <h1>
            Cryptographic performance.
          </h1>

          <p className="muted">
            Run controlled in-container
            benchmarks without crowding
            the main registration workflow.
          </p>

        </div>


        <Benchmark />

      </main>


      <footer className="site-footer">

        <span>
          QuantumProof
        </span>

        <span>
          Benchmark environment
        </span>

      </footer>

    </div>
  );
}


function Home() {

  const [health, setHealth] =
    useState(null);


  useEffect(() => {

    fetch('/health')
      .then(r => r.json())
      .then(setHealth)
      .catch(() => {});

  }, []);


  return (
    <div className="app-shell">

      <header className="site-header">

        <a
          className="brand"
          href="/"
        >

          <span className="brand-mark">
            Q
          </span>

          QuantumProof

        </a>


        <nav className="nav-links">
          <a href="#how-it-works">How it works</a>
          <a href="#security">Security</a>
          <a href="/admin/login">
            Issuer portal
          </a>
        </nav>


        <div className="header-status">

          <i />

          {health
            ? `${health.pqc_backend} · ${health.ledger_backend}`
            : 'Checking service…'}

        </div>

      </header>


      <main>

        <section className="hero">

          <div className="hero-copy">

            <div className="hero-badge">
              <span>●</span>
              TRUSTED DOCUMENT VERIFICATION
            </div>


            <h1>
              Trust the document.
              <br />
              <span>
                Verify the evidence.
              </span>
            </h1>


            <p>
              Issue and verify important documents with a clear,
              independently checkable trail of cryptographic evidence.
            </p>

            <div className="hero-actions">
              <a
                className="primary-button"
                href="/admin/login"
              >
                Open issuer workspace
                <Icon name="arrow" />
              </a>

              <a className="text-link" href="#how-it-works">
                Explore the process <span aria-hidden="true">↓</span>
              </a>
            </div>
          </div>

          <div className="trust-visual" aria-label="Document verification workflow preview">
            <div className="trust-visual-orb" aria-hidden="true" />
            <div className="trust-visual-header">
              <div>
                <span className="visual-overline">QUANTUMPROOF / SYSTEM</span>
                <strong>Verification overview</strong>
              </div>
              <span className="system-live"><i /> {health ? 'CONNECTED' : 'CHECKING'}</span>
            </div>
            <div className="trust-document">
              <span className="document-glyph" aria-hidden="true">PDF</span>
              <div className="document-details">
                <strong>Document evidence</strong>
                <small>Private file · Public proof</small>
              </div>
              <span className="document-check"><Icon name="check" /></span>
            </div>
            <div className="visual-connector" aria-hidden="true"><i /><i /><i /></div>
            <div className="visual-proof-grid">
              <div className="visual-proof-card">
                <span className="proof-symbol hash-symbol" aria-hidden="true">#</span>
                <span><small>INTEGRITY</small><strong>SHA-256</strong></span>
                <i className="proof-state" aria-label="Included" />
              </div>
              <div className="visual-proof-card">
                <span className="proof-symbol signature-symbol" aria-hidden="true">✓</span>
                <span><small>SIGNATURE</small><strong>{health?.signature_algorithm || 'Digital signature'}</strong></span>
                <i className="proof-state" aria-label="Included" />
              </div>
              <div className="visual-proof-card">
                <span className="proof-symbol ledger-symbol" aria-hidden="true">↗</span>
                <span><small>RECORD</small><strong>Ledger</strong></span>
                <i className="proof-state" aria-label="Included" />
              </div>
            </div>
            <div className="trust-visual-footer">
              <span><Icon name="lock" /> Original document stays off-ledger</span>
              <span className="visual-footer-mark">SECURE BY DESIGN</span>
            </div>
          </div>
        </section>

        <section className="home-capabilities" id="security">
          <div className="home-section-heading">
            <div>
              <p className="eyebrow">A BETTER WAY TO PROVE WHAT'S REAL</p>
              <h2>One document. Three layers of evidence.</h2>
            </div>
            <p>Every check has a clear job: protect the file, prove who issued it, and preserve a verifiable record.</p>
          </div>
          <div className="capability-grid">
            <article className="capability-card">
              <span className="capability-icon capability-hash" aria-hidden="true">#</span>
              <span className="capability-index">01 / INTEGRITY</span>
              <h3>Detect the smallest change</h3>
              <p>A SHA-256 fingerprint is recalculated from the document you upload and compared byte-for-byte.</p>
            </article>
            <article className="capability-card">
              <span className="capability-icon capability-sign" aria-hidden="true">✓</span>
              <span className="capability-index">02 / AUTHENTICITY</span>
              <h3>Prove the issuer's signature</h3>
              <p>ML-DSA signing evidence helps a verifier confirm that an authorized issuer created the record.</p>
            </article>
            <article className="capability-card">
              <span className="capability-icon capability-ledger" aria-hidden="true">↗</span>
              <span className="capability-index">03 / TRACEABILITY</span>
              <h3>Keep a tamper-evident trail</h3>
              <p>A compact commitment can be checked against the configured ledger without publishing the PDF.</p>
            </article>
          </div>
        </section>

        <section className="home-workflow" id="how-it-works">
          <div className="workflow-intro">
            <p className="eyebrow">SIMPLE FOR PEOPLE. STRONG ON EVIDENCE.</p>
            <h2>From upload<br />to trusted proof.</h2>
            <p>Issuers create a record once. Anyone with the verification link can check the original document.</p>
            <a className="text-link workflow-link" href="/admin/login">Start in issuer workspace <Icon name="arrow" /></a>
          </div>
          <div className="workflow-steps">
            <article className="workflow-step">
              <span className="workflow-number">01</span>
              <div><h3>Register</h3><p>The issuer uploads a PDF and creates its signed record.</p></div>
              <span className="workflow-arrow" aria-hidden="true">↘</span>
            </article>
            <article className="workflow-step">
              <span className="workflow-number">02</span>
              <div><h3>Share</h3><p>A document ID and QR-ready verification link are generated.</p></div>
              <span className="workflow-arrow" aria-hidden="true">↘</span>
            </article>
            <article className="workflow-step">
              <span className="workflow-number">03</span>
              <div><h3>Verify</h3><p>The recipient uploads their copy to check its evidence.</p></div>
              <span className="workflow-arrow workflow-arrow-last" aria-hidden="true">✓</span>
            </article>
          </div>
        </section>

      </main>


      <footer className="site-footer">

        <span>
          QuantumProof
        </span>

        <span>
          Research prototype · SHA-256 · ML-DSA · ML-KEM · Hyperledger Fabric
        </span>

      </footer>

    </div>
  );
}


const path =
  window.location.pathname;


const verifyMatch =
  path.match(
    /^\/verify\/([0-9a-f-]{36})$/i
  );


const documentMatch =
  path.match(
    /^\/document\/([0-9a-f-]{36})$/i
  );


let app;


if (path === '/admin/login') {

  app = <AdminLoginPage />;

} else if (path === '/admin') {

  app = <AdminRoute><AdminHomeRedirect /></AdminRoute>;

} else if (path === '/admin/issuers') {

  app = <AdminRoute><IssuerManagement /></AdminRoute>;

} else if (verifyMatch) {

  app = (
    <Verify
      documentId={verifyMatch[1]}
    />
  );

} else if (documentMatch) {

  app = (
    <DocumentResult
      documentId={documentMatch[1]}
    />
  );

} else if (path === '/register') {

  app = <AdminRoute><RegisterPage /></AdminRoute>;

} else if (path === '/registry') {

  app = <AdminRoute><RegistryPage /></AdminRoute>;

} else if (path === '/benchmark') {

  app = <AdminRoute><BenchmarkPage /></AdminRoute>;

} else {

  app = <Home />;

}


createRoot(
  document.getElementById('root')
).render(app);

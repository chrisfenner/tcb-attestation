package tcbattestation

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"fmt"
	"math/big"
	"testing"

	"github.com/chrisfenner/tpmdirect/tpm2"
)

var AKTemplate = tpm2.TPM2BPublic{
	PublicArea: tpm2.TPMTPublic{
		Type:    tpm2.TPMAlgECC,
		NameAlg: tpm2.TPMAlgSHA256,
		ObjectAttributes: tpm2.TPMAObject{
			FixedTPM:             true,
			STClear:              false,
			FixedParent:          true,
			SensitiveDataOrigin:  true,
			UserWithAuth:         true,
			AdminWithPolicy:      false,
			NoDA:                 true,
			EncryptedDuplication: false,
			Restricted:           true,
			Decrypt:              false,
			SignEncrypt:          true,
		},
		Parameters: tpm2.TPMUPublicParms{
			ECCDetail: &tpm2.TPMSECCParms{
				Scheme: tpm2.TPMTECCScheme{
					Scheme: tpm2.TPMAlgECDSA,
					Details: tpm2.TPMUAsymScheme{
						ECDSA: &tpm2.TPMSSigSchemeECDSA{
							HashAlg: tpm2.TPMAlgSHA256,
						},
					},
				},
				CurveID: tpm2.TPMECCNistP256,
			},
		},
	},
}

func getAK(tpm tpm2.Interface) (tpm2.TPMHandle, *tpm2.TPM2BPublic, func(), error) {
	createAKCmd := tpm2.CreatePrimaryCommand{
		PrimaryHandle: tpm2.AuthHandle{
			Handle: tpm2.TPMRHOwner,
		},
		InPublic: AKTemplate,
	}
	var createAKRsp tpm2.CreatePrimaryResponse
	if err := tpm.Execute(&createAKCmd, &createAKRsp); err != nil {
		return 0, nil, nil, err
	}
	cleanup := func() {
		flushCmd := tpm2.FlushContextCommand{
			FlushHandle: createAKRsp.ObjectHandle,
		}
		var flushRsp tpm2.FlushContextResponse
		tpm.Execute(&flushCmd, &flushRsp)
	}
	return createAKRsp.ObjectHandle, &createAKRsp.OutPublic, cleanup, nil
}

func getPCRBanks(tpm tpm2.Interface, audit tpm2.Session) (*tpm2.TPMLPCRSelection, error) {
	getCapCmd := tpm2.GetCapabilityCommand{
		Capability:    tpm2.TPMCapPCRs,
		Property:      0,
		PropertyCount: 1,
	}
	var getCapRsp tpm2.GetCapabilityResponse
	if err := tpm.Execute(&getCapCmd, &getCapRsp, audit); err != nil {
		return nil, err
	}
	return getCapRsp.CapabilityData.Data.AssignedPCR, nil
}

func getAudit(tpm tpm2.Interface, nonce []byte, ak tpm2.TPMHandle, auditHandle tpm2.TPMHandle) (*tpm2.TPM2BAttest, *tpm2.TPMTSignature, error) {
	getCmd := tpm2.GetSessionAuditDigestCommand{
		PrivacyAdminHandle: tpm2.AuthHandle{
			Handle: tpm2.TPMRHEndorsement,
		},
		SignHandle: tpm2.AuthHandle{
			Handle: ak,
		},
		SessionHandle:  auditHandle,
		QualifyingData: tpm2.TPM2BData{nonce},
	}
	var getRsp tpm2.GetSessionAuditDigestResponse
	if err := tpm.Execute(&getCmd, &getRsp); err != nil {
		return nil, nil, err
	}
	return &getRsp.AuditInfo, &getRsp.Signature, nil
}

func getQuote(tpm tpm2.Interface, nonce []byte, ak tpm2.TPMHandle, banks *tpm2.TPMLPCRSelection) (*tpm2.TPM2BAttest, *tpm2.TPMTSignature, error) {
	quoteCmd := tpm2.QuoteCommand{
		SignHandle: tpm2.AuthHandle{
			Handle: ak,
		},
		QualifyingData: tpm2.TPM2BData{nonce},
		PCRSelect:      *banks,
	}
	var quoteRsp tpm2.QuoteResponse
	if err := tpm.Execute(&quoteCmd, &quoteRsp); err != nil {
		return nil, nil, err
	}
	return &quoteRsp.Quoted, &quoteRsp.Signature, nil
}

// TPM structures are likely to be flattened when passed to an attestation service. Simulate that here.
type pcrAttestation struct {
	ak       []byte // TPM2B_PUBLIC
	audit    []byte // TPM2B_ATTEST
	auditSig []byte // TPMT_SIGNATURE
	quote    []byte // TPM2B_ATTEST
	quoteSig []byte // TPMT_SIGNATURE
}

func get(thing interface{}) ([]byte, error) {
	var buf bytes.Buffer
	if err := tpm2.Marshal(&buf, thing); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

func getPacket(ak *tpm2.TPM2BPublic, audit, quote *tpm2.TPMSAttest, auditSig, quoteSig *tpm2.TPMTSignature) (*pcrAttestation, error) {
	akB, err := get(ak)
	if err != nil {
		return nil, err
	}
	auditB, err := get(audit)
	if err != nil {
		return nil, err
	}
	auditSigB, err := get(auditSig)
	if err != nil {
		return nil, err
	}
	quoteB, err := get(quote)
	if err != nil {
		return nil, err
	}
	quoteSigB, err := get(quoteSig)
	if err != nil {
		return nil, err
	}
	return &pcrAttestation{
		ak:       akB,
		audit:    auditB,
		auditSig: auditSigB,
		quote:    quoteB,
		quoteSig: quoteSigB,
	}, nil
}

func verifySignature(ak *ecdsa.PublicKey, data, signature []byte) error {
	var sig tpm2.TPMTSignature
	if err := tpm2.Unmarshal(bytes.NewReader(signature), &sig); err != nil {
		return err
	}
	sigR := big.NewInt(0).SetBytes(sig.Signature.ECDSA.SignatureR.Buffer)
	sigS := big.NewInt(0).SetBytes(sig.Signature.ECDSA.SignatureS.Buffer)

	h := sig.Signature.ECDSA.Hash.Hash()
	h.Write(data)
	hash := h.Sum(nil)

	if !ecdsa.Verify(ak, hash, sigR, sigS) {
		return fmt.Errorf("audit signature incorrect")
	}
	return nil
}

func verify(packet *pcrAttestation, nonce []byte) error {
	// Validate the AK is OK before using it.
	var akPub tpm2.TPM2BPublic
	if err := tpm2.Unmarshal(bytes.NewReader(packet.ak), &akPub); err != nil {
		return err
	}
	if attrs := akPub.PublicArea.ObjectAttributes; !attrs.SignEncrypt || !attrs.Restricted || !attrs.FixedTPM || !attrs.FixedParent || !attrs.SensitiveDataOrigin {
		return fmt.Errorf("invalid AK attributes: %v", attrs)
	}
	if nameAlg := akPub.PublicArea.NameAlg; nameAlg != tpm2.TPMAlgSHA256 {
		return fmt.Errorf("invalid AK NameAlg: %v", nameAlg)
	}
	if alg := akPub.PublicArea.Type; alg != tpm2.TPMAlgECC {
		return fmt.Errorf("invalid AK type: %v", alg)
	}
	if curve := akPub.PublicArea.Parameters.ECCDetail.CurveID; curve != tpm2.TPMECCNistP256 {
		return fmt.Errorf("invalid curve ID '%v'", curve)
	}
	ak := ecdsa.PublicKey{
		Curve: elliptic.P256(),
		X:     big.NewInt(0).SetBytes(akPub.PublicArea.Unique.ECC.X.Buffer),
		Y:     big.NewInt(0).SetBytes(akPub.PublicArea.Unique.ECC.Y.Buffer),
	}

	// Validate the two signatures before deserializing them.
	if err := verifySignature(&ak, packet.audit, packet.auditSig); err != nil {
		return fmt.Errorf("audit: %w", err)
	}
	if err := verifySignature(&ak, packet.quote, packet.quoteSig); err != nil {
		return fmt.Errorf("quote: %w", err)
	}

	// Validate the PCR quote
	var quote tpm2.TPMSAttest
	if err := tpm2.Unmarshal(bytes.NewReader(packet.quote), &quote); err != nil {
		return err
	}
	if err := quote.Magic.Check(); err != nil {
		return err
	}
	if !bytes.Equal(quote.ExtraData.Buffer, nonce) {
		return fmt.Errorf("invalid nonce")
	}
	if quote.Type != tpm2.TPMSTAttestQuote {
		return fmt.Errorf("invalid quote attestation type: %x", quote.Type)
	}

	// Validate the audit attestation, i.e., that the TPM reported that the PCR banks
	// that were quoted to us were all of the active PCR banks.
	var auditAttest tpm2.TPMSAttest
	if err := tpm2.Unmarshal(bytes.NewReader(packet.audit), &auditAttest); err != nil {
		return err
	}
	if err := auditAttest.Magic.Check(); err != nil {
		return err
	}
	if !bytes.Equal(auditAttest.ExtraData.Buffer, nonce) {
		return fmt.Errorf("invalid nonce")
	}
	if auditAttest.Type != tpm2.TPMSTAttestSessionAudit {
		return fmt.Errorf("invalid audit attestation type: %x", auditAttest.Type)
	}
	audit := tpm2.NewAudit(tpm2.TPMAlgSHA256)
	getCapCmd := tpm2.GetCapabilityCommand{
		Capability:    tpm2.TPMCapPCRs,
		Property:      0,
		PropertyCount: 1,
	}
	getCapRsp := tpm2.GetCapabilityResponse{
		MoreData: false,
		CapabilityData: tpm2.TPMSCapabilityData{
			Capability: tpm2.TPMCapPCRs,
			Data: tpm2.TPMUCapabilities{
				AssignedPCR: &quote.Attested.Quote.PCRSelect,
			},
		},
	}
	if err := audit.Extend(&getCapCmd, &getCapRsp); err != nil {
		return err
	}
	if !bytes.Equal(auditAttest.Attested.SessionAudit.SessionDigest.Buffer, audit.Digest()) {
		return fmt.Errorf("invalid audit digest")
	}

	var algs []tpm2.TPMAlgID
	for _, selection := range quote.Attested.Quote.PCRSelect.PCRSelections {
		algs = append(algs, selection.Hash)
	}
	fmt.Printf("All active PCR banks: %04x\n", algs)
	fmt.Printf("Digest: %x\n", quote.Attested.Quote.PCRDigest.Buffer)

	return nil

}

func TestPCRAttestation(t *testing.T) {
	tpm, err := tpm2.Open(tpm2.LocalSimulator)
	if err != nil {
		t.Fatalf("could not connect to tpm2.TPM simulator: %v", err)
	}
	defer tpm.Close()

	// Create the AK we'll use to attest the PCRs
	ak, akPub, cleanupAK, err := getAK(tpm)
	if err != nil {
		t.Fatalf("%v", err)
	}
	defer cleanupAK()

	// Create the audit session
	sess, cleanupAudit, err := tpm2.HMACSession(tpm, tpm2.TPMAlgSHA256, 16, tpm2.Audit())
	if err != nil {
		t.Fatalf("%v", err)
	}
	defer cleanupAudit()

	// Ask the TPM which PCR banks are allocated, in the audit session
	banks, err := getPCRBanks(tpm, sess)
	if err != nil {
		t.Fatalf("%v", err)
	}

	// Attestation challenger sends a nonce. For testing, generate it here.
	nonce := make([]byte, 16)
	rand.Read(nonce)

	// Sign the audited GetCapability so the attester can know that's all the PCRs
	audit, auditSig, err := getAudit(tpm, nonce, ak, sess.Handle())
	if err != nil {
		t.Fatalf("%v", err)
	}

	// Quote all the PCRs
	quote, quoteSig, err := getQuote(tpm, nonce, ak, banks)
	if err != nil {
		t.Fatalf("%v", err)
	}

	// Assemble the attestation packet
	packet, err := getPacket(akPub, &audit.AttestationData, &quote.AttestationData, auditSig, quoteSig)
	if err != nil {
		t.Fatalf("%v", err)
	}

	// Attestation challenger verifies the whole attestation statement.
	if err := verify(packet, nonce); err != nil {
		t.Errorf("%v", err)
	}
}

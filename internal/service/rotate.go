package service

import (
	"errors"
	"fmt"
	"strings"

	"scanvault/internal/model"
	"scanvault/internal/store"
)

func (s *Service) RotateSecret(deviceID, secret, operator, reason string) (model.KeyEnvelope, model.RotationRequest, error) {
	if err := s.ValidateOperator(operator); err != nil {
		return model.KeyEnvelope{}, model.RotationRequest{}, err
	}
	if err := model.ValidateSecret(secret); err != nil {
		return model.KeyEnvelope{}, model.RotationRequest{}, err
	}
	device, err := store.GetDevice(s.Store, deviceID)
	if err != nil {
		return model.KeyEnvelope{}, model.RotationRequest{}, err
	}
	if !device.IsUsable() {
		return model.KeyEnvelope{}, model.RotationRequest{}, errors.New("device is not active")
	}
	previous, err := store.ListEnvelopesForDevice(s.Store, deviceID)
	if err != nil {
		return model.KeyEnvelope{}, model.RotationRequest{}, err
	}
	version := 1
	for _, envelope := range previous {
		if envelope.Version >= version {
			version = envelope.Version + 1
		}
		envelope.Active = false
		if err := store.SaveEnvelope(s.Store, envelope); err != nil {
			return model.KeyEnvelope{}, model.RotationRequest{}, err
		}
	}
	wrapped, fingerprint, err := s.Sealer.SealCommunicationSecret(device.PublicKey, secret)
	if err != nil {
		return model.KeyEnvelope{}, model.RotationRequest{}, err
	}
	envelope := model.KeyEnvelope{
		ID:          s.nextID("envelope"),
		DeviceID:    deviceID,
		Version:     version,
		Wrapped:     wrapped,
		Fingerprint: fingerprint,
		Algorithm:   "AES-CTR-SHA256",
		CreatedBy:   operator,
		CreatedAt:   s.Stamp,
		Active:      true,
	}
	if err := store.SaveEnvelope(s.Store, envelope); err != nil {
		return model.KeyEnvelope{}, model.RotationRequest{}, fmt.Errorf("save key envelope: %w", err)
	}
	request := model.RotationRequest{
		ID:          s.nextID("rotation"),
		DeviceID:    deviceID,
		EnvelopeID:  envelope.ID,
		RequestedBy: operator,
		Reason:      strings.TrimSpace(reason),
		State:       "pending",
		CreatedAt:   s.Stamp,
	}
	if err := store.SaveRotation(s.Store, request); err != nil {
		return model.KeyEnvelope{}, model.RotationRequest{}, err
	}
	if _, err := s.Audit.Record("KeyEnvelope", envelope.ID, "rotate", operator, "pending", request.Reason); err != nil {
		return model.KeyEnvelope{}, model.RotationRequest{}, err
	}
	return envelope, request, nil
}

func (s *Service) RecoverSecret(deviceID, privateKey, envelopeID string) (string, error) {
	device, err := store.GetDevice(s.Store, deviceID)
	if err != nil {
		return "", err
	}
	envelope, err := store.GetEnvelope(s.Store, envelopeID)
	if err != nil {
		return "", err
	}
	if envelope.DeviceID != deviceID || !envelope.Active {
		return "", errors.New("envelope is not active for device")
	}
	return s.Sealer.OpenCommunicationSecret(privateKey, device.PublicKey, envelope.Wrapped)
}

func (s *Service) CurrentEnvelope(deviceID string) (model.KeyEnvelope, error) {
	envelopes, err := store.ListEnvelopesForDevice(s.Store, deviceID)
	if err != nil {
		return model.KeyEnvelope{}, err
	}
	for index := len(envelopes) - 1; index >= 0; index-- {
		if envelopes[index].Active {
			return envelopes[index], nil
		}
	}
	return model.KeyEnvelope{}, store.ErrNotFound
}

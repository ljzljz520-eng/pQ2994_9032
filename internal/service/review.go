package service

import (
	"errors"
	"fmt"

	"scanvault/internal/audit"
	"scanvault/internal/model"
	"scanvault/internal/store"
)

func (s *Service) ApproveRotation(rotationID, reviewer, note string) (model.RotationRequest, error) {
	if err := s.ValidateOperator(reviewer); err != nil {
		return model.RotationRequest{}, err
	}
	request, err := store.GetRotation(s.Store, rotationID)
	if err != nil {
		return model.RotationRequest{}, err
	}
	if request.State != "pending" {
		return model.RotationRequest{}, errors.New("rotation is not pending")
	}
	if err := model.CheckStateTransition(request.State, "approved"); err != nil {
		return model.RotationRequest{}, err
	}
	request.State = "approved"
	request.Reviewer = reviewer
	request.Decision = note
	request.DecidedAt = s.Stamp
	if err := store.SaveRotation(s.Store, request); err != nil {
		return model.RotationRequest{}, fmt.Errorf("save approval: %w", err)
	}
	if _, err := s.Audit.Record("RotationRequest", request.ID, "approve", reviewer, "accepted", note); err != nil {
		return model.RotationRequest{}, err
	}
	return request, nil
}

func (s *Service) RejectRotation(rotationID, reviewer, reason string) (model.RotationRequest, error) {
	if err := s.ValidateOperator(reviewer); err != nil {
		return model.RotationRequest{}, err
	}
	request, err := store.GetRotation(s.Store, rotationID)
	if err != nil {
		return model.RotationRequest{}, err
	}
	if request.State != "pending" {
		return model.RotationRequest{}, errors.New("rotation is not pending")
	}
	request.State = "rejected"
	request.Reviewer = reviewer
	request.Decision = reason
	request.DecidedAt = s.Stamp
	if err := store.SaveRotation(s.Store, request); err != nil {
		return model.RotationRequest{}, err
	}
	if _, err := s.Audit.Record("RotationRequest", request.ID, "reject", reviewer, "rejected", reason); err != nil {
		return model.RotationRequest{}, err
	}
	return request, nil
}

func (s *Service) MarkApplied(rotationID, operator string) (model.RotationRequest, error) {
	if err := s.ValidateOperator(operator); err != nil {
		return model.RotationRequest{}, err
	}
	request, err := store.GetRotation(s.Store, rotationID)
	if err != nil {
		return model.RotationRequest{}, err
	}
	if request.State != "approved" {
		return model.RotationRequest{}, errors.New("rotation must be approved before apply")
	}
	request.State = "applied"
	if err := store.SaveRotation(s.Store, request); err != nil {
		return model.RotationRequest{}, err
	}
	if _, err := s.Audit.Record("RotationRequest", request.ID, "apply", operator, "accepted", request.EnvelopeID); err != nil {
		return model.RotationRequest{}, err
	}
	return request, nil
}

func (s *Service) RotationStatus(rotationID string) (string, error) {
	request, err := store.GetRotation(s.Store, rotationID)
	if err != nil {
		return "", err
	}
	return request.State, nil
}

func (s *Service) PendingRotations() ([]model.RotationRequest, error) {
	return store.ListPendingRotations(s.Store)
}

func (s *Service) AllRotations() ([]model.RotationRequest, error) {
	return store.ListRotations(s.Store)
}

func (s *Service) ReviewSummary() (map[string]int, error) {
	rotations, err := s.AllRotations()
	if err != nil {
		return nil, err
	}
	counts := map[string]int{"pending": 0, "approved": 0, "rejected": 0, "applied": 0}
	for _, rotation := range rotations {
		if _, exists := counts[rotation.State]; !exists {
			counts[rotation.State] = 0
		}
		counts[rotation.State]++
	}
	return counts, nil
}

func (s *Service) CanApply(request model.RotationRequest) bool {
	if request.State != "approved" {
		return false
	}
	if request.Reviewer == "" || request.EnvelopeID == "" || request.DeviceID == "" {
		return false
	}
	return true
}

func (s *Service) ReviewAndApply(rotationID, reviewer, operator string) (model.RotationRequest, error) {
	request, err := s.ApproveRotation(rotationID, reviewer, "reviewed and approved")
	if err != nil {
		return model.RotationRequest{}, err
	}
	if !s.CanApply(request) {
		return model.RotationRequest{}, errors.New("approved rotation is not applicable")
	}
	return s.MarkApplied(request.ID, operator)
}

func (s *Service) AuditForRotation(rotationID string) ([]model.AuditEntry, error) {
	entries, err := s.Audit.List()
	if err != nil {
		return nil, err
	}
	return audit.Filter(entries, "RotationRequest", "", ""), nil
}

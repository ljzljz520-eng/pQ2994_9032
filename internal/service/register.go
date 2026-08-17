package service

import (
	"errors"
	"fmt"
	"strings"

	"scanvault/internal/model"
	"scanvault/internal/store"
)

func (s *Service) RegisterDevice(serial, name, publicKey, location, owner, operator string) (model.Device, error) {
	if err := s.ValidateOperator(operator); err != nil {
		return model.Device{}, err
	}
	device := model.Device{
		ID:         s.nextID("device"),
		Serial:     model.NormalizeSerial(serial),
		Name:       strings.TrimSpace(name),
		PublicKey:  strings.TrimSpace(publicKey),
		Status:     "active",
		Location:   strings.TrimSpace(location),
		Owner:      strings.TrimSpace(owner),
		Registered: s.Stamp,
	}
	if err := model.ValidateDevice(device); err != nil {
		return model.Device{}, err
	}
	if _, err := store.FindDeviceBySerial(s.Store, device.Serial); err == nil {
		return model.Device{}, errors.New("device serial already registered")
	} else if !errors.Is(err, store.ErrNotFound) {
		return model.Device{}, err
	}
	if err := store.SaveDevice(s.Store, device); err != nil {
		return model.Device{}, fmt.Errorf("register device: %w", err)
	}
	if _, err := s.Audit.Record("Device", device.ID, "register", operator, "accepted", device.Serial); err != nil {
		return model.Device{}, err
	}
	return device, nil
}

func (s *Service) GetDevice(id string) (model.Device, error) {
	return store.GetDevice(s.Store, id)
}

func (s *Service) SuspendDevice(id, operator, reason string) error {
	if err := s.ValidateOperator(operator); err != nil {
		return err
	}
	device, err := store.GetDevice(s.Store, id)
	if err != nil {
		return err
	}
	if device.Status == "retired" {
		return errors.New("retired device cannot be suspended")
	}
	device.Status = "suspended"
	device.LastChanged = s.Stamp
	if err := store.SaveDevice(s.Store, device); err != nil {
		return err
	}
	_, err = s.Audit.Record("Device", id, "suspend", operator, "accepted", reason)
	return err
}

func (s *Service) RetireDevice(id, operator string) error {
	if err := s.ValidateOperator(operator); err != nil {
		return err
	}
	device, err := store.GetDevice(s.Store, id)
	if err != nil {
		return err
	}
	if device.Status == "retired" {
		return errors.New("device is already retired")
	}
	device.Status = "retired"
	device.LastChanged = s.Stamp
	if err := store.SaveDevice(s.Store, device); err != nil {
		return err
	}
	_, err = s.Audit.Record("Device", id, "retire", operator, "accepted", "retired by operator")
	return err
}

func (s *Service) UpdateLocation(id, location, operator string) (model.Device, error) {
	if err := s.ValidateOperator(operator); err != nil {
		return model.Device{}, err
	}
	device, err := store.GetDevice(s.Store, id)
	if err != nil {
		return model.Device{}, err
	}
	location = strings.TrimSpace(location)
	if location == "" {
		return model.Device{}, errors.New("location is required")
	}
	old := device.Location
	device.Location = location
	device.LastChanged = s.Stamp
	if err := store.SaveDevice(s.Store, device); err != nil {
		return model.Device{}, err
	}
	_, err = s.Audit.Record("Device", id, "relocate", operator, "accepted", old+" -> "+location)
	return device, err
}

func (s *Service) ListDevices() ([]model.Device, error) {
	return store.ListDevices(s.Store)
}

func (s *Service) ListUsableDevices() ([]model.Device, error) {
	devices, err := store.ListDevices(s.Store)
	if err != nil {
		return nil, err
	}
	result := make([]model.Device, 0, len(devices))
	for _, device := range devices {
		if device.IsUsable() {
			result = append(result, device)
		}
	}
	return result, nil
}

func (s *Service) FindBySerial(serial string) (model.Device, error) {
	return store.FindDeviceBySerial(s.Store, serial)
}

func (s *Service) ChangeOwner(id, owner, operator string) (model.Device, error) {
	if err := s.ValidateOperator(operator); err != nil {
		return model.Device{}, err
	}
	owner = strings.TrimSpace(owner)
	if owner == "" {
		return model.Device{}, errors.New("owner is required")
	}
	device, err := store.GetDevice(s.Store, id)
	if err != nil {
		return model.Device{}, err
	}
	previous := device.Owner
	device.Owner = owner
	device.LastChanged = s.Stamp
	if err := store.SaveDevice(s.Store, device); err != nil {
		return model.Device{}, err
	}
	_, err = s.Audit.Record("Device", id, "owner_change", operator, "accepted", previous+" -> "+owner)
	return device, err
}

func (s *Service) ReactivateDevice(id, operator string) (model.Device, error) {
	if err := s.ValidateOperator(operator); err != nil {
		return model.Device{}, err
	}
	device, err := store.GetDevice(s.Store, id)
	if err != nil {
		return model.Device{}, err
	}
	if device.Status == "retired" {
		return model.Device{}, errors.New("retired device cannot reactivate")
	}
	if device.Status == "active" {
		return device, nil
	}
	device.Status = "active"
	device.LastChanged = s.Stamp
	if err := store.SaveDevice(s.Store, device); err != nil {
		return model.Device{}, err
	}
	_, err = s.Audit.Record("Device", id, "reactivate", operator, "accepted", "maintenance complete")
	return device, err
}

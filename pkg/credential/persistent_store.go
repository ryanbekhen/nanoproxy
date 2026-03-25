package credential

// PersistentStore provides durable storage for proxy user credential snapshots.
type PersistentStore interface {
	Load() (map[string]string, error)
	Save(snapshot map[string]string) error
}

func LoadInto(persistentStore PersistentStore, store *StaticCredentialStore) error {
	if store == nil || persistentStore == nil {
		return nil
	}

	snapshot, err := persistentStore.Load()
	if err != nil {
		return err
	}

	store.Replace(snapshot)
	return nil
}

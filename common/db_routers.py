class AppLabelBaseMappingRouter(object):
    """
    A router to control all database operations on models in the
    auth_server application.
    """
    app_mapping = {}

    def db_for_read(self, model, **hints):
        return self.app_mapping.get(model._meta.app_label, None)

    def db_for_write(self, model, **hints):
        return self.app_mapping.get(model._meta.app_label, None)

    def allow_relation(self, obj1, obj2, **hints):
        if self.app_mapping.get(obj1._meta.app_label, None) == self.app_mapping.get(obj2._meta.app_label, None):
            return True
        return None

    def add_mapping(self, app_label, app):
        self.app_mapping.update(dict([(app_label, app)]))


router = AppLabelBaseMappingRouter()


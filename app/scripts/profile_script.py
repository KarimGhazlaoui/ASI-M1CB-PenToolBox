import os
import json

class Profile:
    def __init__(self, profile_path):
        self.profile_path = profile_path

    def save_profile(self, variables, profile_name):
        # Add the profile name to the variables
        variables['profile_name'] = profile_name
        
        # Save the variables to the profile file
        filename = os.path.join(self.profile_path, profile_name + '.kgb')
        with open(filename, 'w') as file:
            json.dump(variables, file)
        print(f"Profil '{profile_name}' sauvegardé avec succès.")

    def load_profile(self, profile_name):
        filename = os.path.join(self.profile_path, profile_name + '.kgb')
        if os.path.exists(filename):
            with open(filename, 'r') as file:
                return json.load(file)
        else:
            print(f"Profil '{profile_name}' n'existe pas.")
            return None

    def list_profiles(self):
        if not os.path.exists(self.profile_path) or not os.listdir(self.profile_path):
            print("No profiles found.")
            return []
        
        profile_names = []
        for file in os.listdir(self.profile_path):
            if file.endswith('.kgb'):
                loaded_variables = self.load_profile(file[:-4])  # Remove the '.kgb' extension
                if loaded_variables and 'profile_name' in loaded_variables:
                    profile_names.append(loaded_variables['profile_name'])
        return profile_names

    def add_or_update_variable(self, profile_name, variable_name, variable_value):
        loaded_variables = self.load_profile(profile_name)
        if loaded_variables:
            loaded_variables[variable_name] = variable_value
            self.save_profile(loaded_variables, profile_name)
            print(f"Variable '{variable_name}' ajouté/mise à jour dans le profil '{profile_name}'.")
        else:
            print(f"Echec de l'ajout/mise à jour de la variable : '{variable_name}' dans le profil '{profile_name}': Profile inexistant.")

    def load_variable(self, profile_name, variable_name):
        filename = os.path.join(self.profile_path, profile_name + '.kgb')
        if os.path.exists(filename):
            with open(filename, 'r') as file:
                data = json.load(file)
                return data.get(variable_name)  # Return None if variable doesn't exist
        else:
            print(f"Le profil : '{profile_name}' n'existe pas.")
            return None
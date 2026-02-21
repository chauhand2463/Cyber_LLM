import utils.constants
import shutil
import os

# Get path to the script folder
script_folder = os.path.dirname(os.path.abspath(__file__))
working_folder = os.path.join(script_folder, "../" + utils.constants.LLM_WORKING_FOLDER)
llm_config = {
    "model": utils.constants.OPENAI_MODEL_NAME or "llama-3.3-70b-versatile",
    "base_url": utils.constants.OPENAI_API_BASE or "https://api.groq.com/openai/v1",
    "api_key": utils.constants.GROQ_API_KEY or utils.constants.OPENAI_API_KEY,
    "cache_seed": None,
    "temperature": 0.2,
    "max_tokens": 256,
}

fast_llm_config = llm_config.copy()
fast_llm_config["model"] = "llama-3.1-8b-instant"

# if utils.constants.OPENAI_API_BASE:
#     llm_config["base_url"] = utils.constants.OPENAI_API_BASE


def clean_working_directory(agent_subfolder: str):
    # Check if the folder exists
    working_subfolder = working_folder + agent_subfolder

    # Avoid accidental deletion of the root folder
    if working_subfolder == "":
        print("Cannot delete the root folder.")
        return

    if not os.path.exists(working_subfolder):
        # Create the folder if it doesn't exist
        try:
            os.makedirs(working_subfolder, exist_ok=True)
            print(f"Created folder {working_subfolder}")
        except Exception as e:
            print(f"Failed to create {working_subfolder}. Reason: {e}")
        return

    # Loop through all the items in the folder
    for filename in os.listdir(working_subfolder):
        file_path = os.path.join(working_subfolder, filename)
        try:
            # If it's a file, remove it
            if os.path.isfile(file_path) or os.path.islink(file_path):
                os.unlink(file_path)
            # If it's a directory, remove it and all its contents
            elif os.path.isdir(file_path):
                shutil.rmtree(file_path)
        except Exception as e:
            print(f"Failed to delete {file_path}. Reason: {e}")

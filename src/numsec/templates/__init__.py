"""Project templates for Numsec."""
import shutil
import subprocess
from pathlib import Path
from typing import List

from ..exceptions import TemplateError

def get_available_templates() -> List[str]:
    """Get a list of available project templates.
    
    Returns:
        List of available template names.
    """
    templates_dir = Path(__file__).parent / "templates"
    if not templates_dir.exists():
        return []
    
    return [
        d.name 
        for d in templates_dir.iterdir() 
        if d.is_dir() and not d.name.startswith("__")
    ]

def validate_template(template_name: str) -> bool:
    """Check if a template exists.
    
    Args:
        template_name: Name of the template to check.
        
    Returns:
        True if the template exists, False otherwise.
    """
    return template_name in get_available_templates()

def get_template_path(template_name: str) -> Path:
    """Get the filesystem path to a template.
    
    Args:
        template_name: Name of the template.
        
    Returns:
        Path to the template directory.
        
    Raises:
        TemplateError: If the template doesn't exist.
    """
    if not validate_template(template_name):
        raise TemplateError(f"Template '{template_name}' not found.")
    
    return Path(__file__).parent / "templates" / template_name

def init_project(project_path: Path, template_name: str = "basic") -> None:
    """Initialize a new project from a template.
    
    Args:
        project_path: Path where the project should be created.
        template_name: Name of the template to use.
        
    Raises:
        TemplateError: If there's an error initializing the project.
    """
    try:
        # Ensure the template exists
        template_path = get_template_path(template_name)
        
        # Create the project directory
        project_path.mkdir(parents=True, exist_ok=True)
        
        # Copy template files
        for item in template_path.iterdir():
            dest_name = "numsec" if item.name == "openspec" else item.name
            dest = project_path / dest_name
            if item.is_dir():
                shutil.copytree(item, dest, dirs_exist_ok=True)
            else:
                shutil.copy2(item, dest)

        numsec_dir = project_path / "numsec"
        if numsec_dir.exists():
            specs_dir = numsec_dir / "specs"
            if specs_dir.exists():
                shutil.rmtree(specs_dir)

            (numsec_dir / "changes").mkdir(parents=True, exist_ok=True)
                
        # Initialize git repository
        subprocess.run(["git", "init"], cwd=str(project_path), check=False)
        
    except Exception as e:
        raise TemplateError(f"Failed to initialize project: {str(e)}")

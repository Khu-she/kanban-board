package com.kanban.server.services;

import com.kanban.server.models.task.TaskDAO;
import com.kanban.server.models.task.TaskDTO;
import com.kanban.server.repository.TaskRepository;
import com.kanban.server.repository.UserRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Service;

import java.util.ArrayList;
import java.util.List;

@Service
public class TaskService {
    @Autowired
    TaskRepository taskRepository;
    @Autowired
    UserRepository userRepository;

    public TaskDTO addTask(TaskDTO task) {
        TaskDAO taskDAO= taskRepository.save(TaskDAO.builder().title(task.getTitle()).description(task.getDescription()).status(task.getStatus()).assignedTo( task.getAssignedTo()).build());
        return TaskDTO.builder().id(taskDAO.getId()).title(taskDAO.getTitle()).description(taskDAO.getDescription()).status(taskDAO.getStatus()).assignedTo(taskDAO.getAssignedTo()).build();
    }
    public List<TaskDTO> getAllTasks(){
        List<TaskDTO> taskDTOS= new ArrayList <>();
       taskRepository.findAll().forEach(taskDAO ->
               taskDTOS.add(TaskDTO.builder().id(taskDAO.getId()).title(taskDAO.getTitle()).description(taskDAO.getDescription()).status(taskDAO.getStatus()).assignedTo( taskDAO.getAssignedTo()).build()
               ));
        return taskDTOS;
    }
    public TaskDTO updateTaskStatus(Long id,String status){
        TaskDAO taskDAO=taskRepository.findById(id).get();
        taskDAO.setStatus(status);
        taskRepository.save(taskDAO);
        return TaskDTO.builder().id(taskDAO.getId()).title(taskDAO.getTitle()).description(taskDAO.getDescription()).status(taskDAO.getStatus()).assignedTo( taskDAO.getAssignedTo()).build();
    }
    public TaskDTO updateTask(Long id,TaskDTO task){

        TaskDAO taskDAO=taskRepository.findById(id).get();
        taskDAO.setTitle(task.getTitle());
        taskDAO.setDescription(task.getDescription());
        taskDAO.setStatus(task.getStatus());
        taskDAO.setAssignedTo(task.getAssignedTo());

        taskRepository.save(taskDAO);
        return TaskDTO.builder().id(taskDAO.getId ()).title(taskDAO.getTitle()).description(taskDAO.getDescription()).status(taskDAO.getStatus()).assignedTo( taskDAO.getAssignedTo()).build();
    }
    public void deleteTask(Long id){
        taskRepository.deleteById(id);
    }

}
